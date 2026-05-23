#include "cilium_endpoint_client.h"

#include <arpa/inet.h>
#include <nlohmann/json.hpp>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kota {

namespace {

bool cilium_allow_list_fallback() noexcept
{
    const char *e = std::getenv("KOTA_CILIUM_ALLOW_LIST_FALLBACK");
    if (!e || !*e)
        return false;
    return e[0] == '1' || e[0] == 't' || e[0] == 'T' || e[0] == 'y' || e[0] == 'Y';
}

static bool ascii_iequals(std::string_view a, std::string_view b)
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

/* RFC 7230: transfer-coding names are case-insensitive (e.g. "Chunked"). */
static bool ascii_icontains(std::string_view haystack, std::string_view needle)
{
    if (needle.empty() || haystack.size() < needle.size())
        return false;
    for (size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (std::tolower(static_cast<unsigned char>(haystack[i + j])) !=
                std::tolower(static_cast<unsigned char>(needle[j]))) {
                match = false;
                break;
            }
        }
        if (match)
            return true;
    }
    return false;
}

/* First line looks like "HEXDIG* [ ; ext ] CRLF" (chunk-size), not JSON. */
static bool looks_like_chunked_body_prefix(std::string_view in)
{
    size_t i = 0;
    while (i < in.size() && (in[i] == ' ' || in[i] == '\t'))
        ++i;
    const size_t hex0 = i;
    while (i < in.size() && std::isxdigit(static_cast<unsigned char>(in[i])))
        ++i;
    if (i == hex0)
        return false;
    while (i < in.size() && in[i] != '\r')
        ++i;
    return i + 1 < in.size() && in[i] == '\r' && in[i + 1] == '\n';
}

/* True if header block contains "Transfer-Encoding: chunked" (HTTP/1.1). */
static bool headers_have_chunked_encoding(std::string_view headers)
{
    for (size_t pos = 0; pos < headers.size();) {
        const auto line_end = headers.find("\r\n", pos);
        if (line_end == std::string_view::npos)
            break;
        std::string_view line = headers.substr(pos, line_end - pos);
        pos = line_end + 2;
        const auto colon = line.find(':');
        if (colon == std::string_view::npos)
            continue;
        std::string_view key = line.substr(0, colon);
        while (!key.empty() && (key.front() == ' ' || key.front() == '\t'))
            key.remove_prefix(1);
        while (!key.empty() && (key.back() == ' ' || key.back() == '\t'))
            key.remove_suffix(1);
        if (!ascii_iequals(key, "transfer-encoding"))
            continue;
        std::string_view val = line.substr(colon + 1);
        while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
            val.remove_prefix(1);
        return ascii_icontains(val, "chunked");
    }
    return false;
}

static std::optional<size_t> header_content_length(std::string_view headers)
{
    for (size_t pos = 0; pos < headers.size();) {
        const auto line_end = headers.find("\r\n", pos);
        if (line_end == std::string_view::npos)
            break;
        std::string_view line = headers.substr(pos, line_end - pos);
        pos = line_end + 2;
        const auto colon = line.find(':');
        if (colon == std::string_view::npos)
            continue;
        std::string_view key = line.substr(0, colon);
        while (!key.empty() && (key.front() == ' ' || key.front() == '\t'))
            key.remove_prefix(1);
        while (!key.empty() && (key.back() == ' ' || key.back() == '\t'))
            key.remove_suffix(1);
        if (!ascii_iequals(key, "content-length"))
            continue;
        std::string_view val = line.substr(colon + 1);
        while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
            val.remove_prefix(1);
        char *endp = nullptr;
        const unsigned long n = std::strtoul(std::string(val).c_str(), &endp, 10);
        if (endp && *endp == '\0' && n < SIZE_MAX)
            return static_cast<size_t>(n);
    }
    return std::nullopt;
}

/* RFC 7230 chunked decoding for bodies after the header block. */
static std::expected<std::string, std::string> decode_chunked_body(std::string_view in)
{
    std::string out;
    out.reserve(in.size());
    size_t pos = 0;
    for (;;) {
        const auto line_end = in.find("\r\n", pos);
        if (line_end == std::string_view::npos)
            return std::unexpected("chunked: missing chunk-size line terminator");
        std::string_view line = in.substr(pos, line_end - pos);
        pos = line_end + 2;
        const auto semi = line.find(';');
        if (semi != std::string_view::npos)
            line = line.substr(0, semi);
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t'))
            line.remove_prefix(1);
        while (!line.empty() && (line.back() == ' ' || line.back() == '\t'))
            line.remove_suffix(1);
        if (line.empty())
            return std::unexpected("chunked: empty chunk-size line");
        char *endhex = nullptr;
        const unsigned long chunk_len = std::strtoul(std::string(line).c_str(), &endhex, 16);
        if (endhex == nullptr || *endhex != '\0')
            return std::unexpected("chunked: invalid chunk size hex");
        if (chunk_len == 0) {
            /* Optional trailers; consume until blank line or end. */
            return out;
        }
        if (pos + chunk_len > in.size())
            return std::unexpected("chunked: short body for declared chunk");
        out.append(in.data() + pos, chunk_len);
        pos += chunk_len;
        if (pos + 2 > in.size() || in[pos] != '\r' || in[pos + 1] != '\n')
            return std::unexpected("chunked: missing CRLF after chunk data");
        pos += 2;
    }
}

static std::expected<std::string, std::string> extract_http_body(std::string_view headers,
                                                                 std::string_view raw_after_headers)
{
    if (headers_have_chunked_encoding(headers) ||
        looks_like_chunked_body_prefix(raw_after_headers))
    {
        return decode_chunked_body(raw_after_headers);
    }
    if (auto n = header_content_length(headers)) {
        if (*n > raw_after_headers.size())
            return std::unexpected("HTTP Content-Length larger than received body");
        return std::string{raw_after_headers.substr(0, *n)};
    }
    return std::string{raw_after_headers};
}

static int http_status_from_response(std::string_view resp)
{
    const auto line_end = resp.find("\r\n");
    if (line_end == std::string_view::npos || line_end < 12)
        return -1;
    const std::string_view line{resp.data(), line_end};
    size_t               i = line.find(' ');
    if (i == std::string_view::npos)
        return -1;
    ++i;
    while (i < line.size() && line[i] == ' ')
        ++i;
    if (i + 2 >= line.size())
        return -1;
    if (!std::isdigit(static_cast<unsigned char>(line[i])) ||
        !std::isdigit(static_cast<unsigned char>(line[i + 1])) ||
        !std::isdigit(static_cast<unsigned char>(line[i + 2])))
        return -1;
    return (line[i] - '0') * 100 + (line[i + 1] - '0') * 10 + (line[i + 2] - '0');
}

static std::expected<std::pair<int, std::string>, std::string>
http_unix_exchange(const std::string &socket_path, std::string_view request_path)
{
    if (socket_path.size() >= sizeof(sockaddr_un{}.sun_path))
        return std::unexpected("Cilium socket path too long for sockaddr_un");

    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return std::unexpected(std::string("socket(AF_UNIX): ") + std::strerror(errno));

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);
    if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
        int e = errno;
        ::close(fd);
        return std::unexpected(std::string("connect(") + socket_path + "): " +
                               std::strerror(e));
    }

    std::string req = "GET ";
    req.append(request_path);
    req += " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    const char *p   = req.data();
    size_t      rem = req.size();
    while (rem > 0) {
        ssize_t n = ::send(fd, p, rem, 0);
        if (n < 0) {
            int e = errno;
            ::close(fd);
            return std::unexpected(std::string("send: ") + std::strerror(e));
        }
        if (n == 0) {
            ::close(fd);
            return std::unexpected("send: short write");
        }
        p += static_cast<size_t>(n);
        rem -= static_cast<size_t>(n);
    }

    std::string resp;
    resp.reserve(65536);
    std::vector<char> buf(64 * 1024);
    for (;;) {
        ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
        if (n < 0) {
            int e = errno;
            ::close(fd);
            return std::unexpected(std::string("recv: ") + std::strerror(e));
        }
        if (n == 0)
            break;
        resp.append(buf.data(), static_cast<size_t>(n));
    }
    ::close(fd);

    const auto sep = resp.find("\r\n\r\n");
    if (sep == std::string::npos)
        return std::unexpected("HTTP response: no header/body separator");

    const int status = http_status_from_response(resp);
    if (status < 0)
        return std::unexpected("HTTP response: bad status line");

    const std::string_view headers{resp.data(), sep};
    const std::string_view raw_body{resp.data() + sep + 4, resp.size() - (sep + 4)};
    auto                   body = extract_http_body(headers, raw_body);
    if (!body)
        return std::unexpected(body.error());
    return std::pair<int, std::string>{status, std::move(*body)};
}

static std::expected<std::string, std::string>
http_get_unix(const std::string &socket_path, std::string_view request_path)
{
    auto ex = http_unix_exchange(socket_path, request_path);
    if (!ex)
        return std::unexpected(ex.error());
    if (ex->first != 200)
        return std::unexpected(std::string("Cilium API HTTP status ") + std::to_string(ex->first));
    return std::move(ex->second);
}

std::string profile_from_security_relevant(const nlohmann::json &status)
{
    if (!status.contains("labels") || !status["labels"].is_object())
        return {};
    const auto &l = status["labels"];
    if (!l.contains("security-relevant") || !l["security-relevant"].is_array())
        return {};
    constexpr std::string_view prefix = "k8s:kota.ai/profile=";
    for (const auto &e : l["security-relevant"]) {
        if (!e.is_string())
            continue;
        const std::string s = e.get<std::string>();
        if (s.size() > prefix.size() && s.compare(0, prefix.size(), prefix) == 0)
            return s.substr(prefix.size());
    }
    return {};
}

static bool external_id_matches_container(const nlohmann::json &ext,
                                            const std::string &container_id_64)
{
    if (ext.contains("container-id") && ext["container-id"].is_string() &&
        ext["container-id"].get<std::string>() == container_id_64)
        return true;
    /* Some builds expose only cni-attachment-id "<64hex>:<ifname>". */
    if (ext.contains("cni-attachment-id") && ext["cni-attachment-id"].is_string()) {
        const std::string a = ext["cni-attachment-id"].get<std::string>();
        if (a.size() >= container_id_64.size() &&
            a.compare(0, container_id_64.size(), container_id_64) == 0 &&
            (a.size() == container_id_64.size() || a[container_id_64.size()] == ':'))
            return true;
    }
    return false;
}

std::optional<CiliumEndpointFields> parse_matched(const nlohmann::json &ep,
                                                  const std::string &container_id_64)
{
    if (!ep.is_object() || !ep.contains("status"))
        return std::nullopt;
    const auto &st = ep["status"];
    if (!st.is_object() || !st.contains("external-identifiers") ||
        !st["external-identifiers"].is_object())
        return std::nullopt;
    const auto &ext = st["external-identifiers"];
    if (!external_id_matches_container(ext, container_id_64))
        return std::nullopt;

    CiliumEndpointFields out{};
    if (st.contains("state") && st["state"].is_string() &&
        st["state"].get<std::string>() != "ready")
    {
        /* still use data; Cilium can report work-in-progress. */
    }

    if (st.contains("identity") && st["identity"].is_object() &&
        st["identity"].contains("id") && st["identity"]["id"].is_number()) {
        const uint64_t id = st["identity"]["id"].get<uint64_t>();
        if (id <= 0xFFFFFFFFu)
            out.identity_id = static_cast<uint32_t>(id);
    }

    if (ext.contains("k8s-pod-name") && ext["k8s-pod-name"].is_string())
        out.pod_name = ext["k8s-pod-name"].get<std::string>();
    if (ext.contains("k8s-namespace") && ext["k8s-namespace"].is_string())
        out.namespace_name = ext["k8s-namespace"].get<std::string>();

    if (out.namespace_name.empty() && ext.contains("pod-name") &&
        ext["pod-name"].is_string()) {
        const std::string pn = ext["pod-name"].get<std::string>();
        const auto        sl = pn.find('/');
        if (sl != std::string::npos && sl > 0 && sl + 1 < pn.size()) {
            out.namespace_name = pn.substr(0, sl);
            out.pod_name       = pn.substr(sl + 1);
        }
    }

    if (!st.contains("networking") || !st["networking"].is_object())
        return std::nullopt;
    const auto &n = st["networking"];
    if (n.contains("addressing") && n["addressing"].is_array()) {
        for (const auto &a : n["addressing"]) {
            if (!a.is_object() || !a.contains("ipv4"))
                continue;
            if (a["ipv4"].is_string()) {
                out.pod_ip = a["ipv4"].get<std::string>();
                break;
            }
        }
    }
    if (out.pod_ip.empty()) {
        /* Optional: "ipv4" may appear under different schema versions. */
        return std::nullopt;
    }
    {
        struct in_addr tmp {};
        if (::inet_pton(AF_INET, out.pod_ip.c_str(), &tmp) != 1)
            return std::nullopt;
    }

    if (n.contains("interface-name") && n["interface-name"].is_string())
        out.host_veth_ifname = n["interface-name"].get<std::string>();

    out.profile_label = profile_from_security_relevant(st);
    if (out.pod_name.empty())
        out.pod_name = "unknown";
    if (out.namespace_name.empty())
        out.namespace_name = "unknown";
    return out;
}

/* GET /v1/endpoint is one large array per node; without caching every lookup
 * re-fetches and re-parses (see docs/tasks/feedback.md). */
struct EndpointArrayCache {
    std::mutex                              mu;
    std::string                             last_socket;
    nlohmann::json                          list;
    std::chrono::steady_clock::time_point  fetched_at{};
    bool                                    valid{false};
};

static EndpointArrayCache s_ep_cache;

static std::expected<const nlohmann::json *, std::string>
get_or_refresh_endpoint_array(const std::string &socket_path, bool bypass_cache)
{
    using clock = std::chrono::steady_clock;
    constexpr auto kTtl = std::chrono::milliseconds(750);

    std::lock_guard<std::mutex> lock(s_ep_cache.mu);
    const auto now = clock::now();
    if (!bypass_cache && s_ep_cache.valid && s_ep_cache.last_socket == socket_path &&
        s_ep_cache.list.is_array() && now - s_ep_cache.fetched_at < kTtl)
    {
        return &s_ep_cache.list;
    }

    auto body = http_get_unix(socket_path, "/v1/endpoint");
    if (!body)
        return std::unexpected(body.error());
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(*body);
    } catch (const std::exception &e) {
        return std::unexpected(std::string("JSON: ") + e.what());
    }
    if (!j.is_array())
        return std::unexpected("Cilium /v1/endpoint: expected JSON array");
    s_ep_cache.list        = std::move(j);
    s_ep_cache.last_socket = socket_path;
    s_ep_cache.fetched_at  = now;
    s_ep_cache.valid       = true;
    return &s_ep_cache.list;
}

/* GET /v1/endpoint/container-id:{cid} — single Endpoint JSON (Cilium OpenAPI path param). */
struct ContainerPrefixOutcome {
    enum class Kind { NotFound404, UseFullList, Found } kind{Kind::UseFullList};
    CiliumEndpointFields                      fields{};
};

static std::expected<ContainerPrefixOutcome, std::string>
try_get_endpoint_by_container_prefix(const std::string &socket_path,
                                     const std::string &container_id_64)
{
    std::string path = "/v1/endpoint/container-id:";
    path += container_id_64;
    auto hx = http_unix_exchange(socket_path, path);
    if (!hx)
        return std::unexpected(hx.error());

    const int st = hx->first;
    if (st == 404) {
        ContainerPrefixOutcome out{};
        out.kind = ContainerPrefixOutcome::Kind::NotFound404;
        return out;
    }
    if (st != 200) {
        if (st == 400 || st == 405) {
            ContainerPrefixOutcome out{};
            out.kind = ContainerPrefixOutcome::Kind::UseFullList;
            return out;
        }
        return std::unexpected(std::string("Cilium prefix GET HTTP ") + std::to_string(st));
    }

    nlohmann::json j;
    try {
        j = nlohmann::json::parse(hx->second);
    } catch (const std::exception &e) {
        return std::unexpected(std::string("JSON: ") + e.what());
    }
    if (!j.is_object()) {
        ContainerPrefixOutcome out{};
        out.kind = ContainerPrefixOutcome::Kind::UseFullList;
        return out;
    }
    if (auto parsed = parse_matched(j, container_id_64)) {
        if (!parsed->pod_ip.empty()) {
            ContainerPrefixOutcome out{};
            out.kind   = ContainerPrefixOutcome::Kind::Found;
            out.fields = std::move(*parsed);
            return out;
        }
    }
    ContainerPrefixOutcome out{};
    out.kind = ContainerPrefixOutcome::Kind::UseFullList;
    return out;
}

} // namespace

std::expected<std::optional<CiliumEndpointFields>, std::string>
cilium_find_endpoint_by_container_id(const std::string &socket_path,
                                     const std::string &container_id_64,
                                     const bool bypass_cache)
{
    if (container_id_64.size() != 64)
        return std::unexpected("container id must be 64 hex chars");

    auto pr = try_get_endpoint_by_container_prefix(socket_path, container_id_64);
    if (!pr)
        return std::unexpected(pr.error());
    if (pr->kind == ContainerPrefixOutcome::Kind::NotFound404)
        return std::optional<CiliumEndpointFields>{std::nullopt};
    if (pr->kind == ContainerPrefixOutcome::Kind::Found)
        return std::optional<CiliumEndpointFields>{std::move(pr->fields)};

    if (!cilium_allow_list_fallback())
        return std::optional<CiliumEndpointFields>{std::nullopt};

    auto jptr = get_or_refresh_endpoint_array(socket_path, bypass_cache);
    if (!jptr)
        return std::unexpected(jptr.error());
    for (const auto &ep : **jptr) {
        if (auto parsed = parse_matched(ep, container_id_64)) {
            if (!parsed->pod_ip.empty())
                return std::optional<CiliumEndpointFields>{*parsed};
        }
    }
    return std::optional<CiliumEndpointFields>{std::nullopt};
}

} // namespace kota
