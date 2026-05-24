#include "pod_resolver.h"

#include "cilium_endpoint_client.h"
#include "../maps/map_updater.h"
#include "../policy/profile_registry.h"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <chrono>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include "../../../include/shared/kota_common.h"

namespace kota {

namespace fs = std::filesystem;

/* Set KOTA_LOG_RESOLVE_TIMING for stderr: cgroup_prefix µs, each identity layer total,
 * resolve_total, plus finer lines inside Cilium-UDS / OCI-proc backends. */
static bool resolve_timing_enabled() noexcept
{
    return std::getenv("KOTA_LOG_RESOLVE_TIMING") != nullptr;
}

/* Total wait budget when the first UDS attempt returns no endpoint (race with
 * Cilium publishing). Default 15ms; 0 disables sleeps. For values >=2ms the wait
 * is split in half with a bypass refetch in between (see CiliumUdsIdentityBackend).
 * Clamped 0–250. */
static int cilium_uds_retry_sleep_ms() noexcept
{
    const char *e = std::getenv("KOTA_CILIUM_UDS_RETRY_SLEEP_MS");
    if (!e || !*e)
        return 15;
    char *endp = nullptr;
    const long v = std::strtol(e, &endp, 10);
    if (endp == e)
        return 15;
    if (v < 0)
        return 0;
    if (v > 250)
        return 250;
    return static_cast<int>(v);
}

extern "C" void kota_on_host_veth_resolved(uint64_t cgroup_inode,
                                           const char *ifname)
    __attribute__((weak));
extern "C" void kota_on_cgroup_removed(uint64_t cgroup_inode)
    __attribute__((weak));

/* Birth workers call resolve() concurrently; setns + libc net io must not overlap. */
static std::mutex s_netns_ip_mu;

// ── Inode → path cache + pod-parent fast path ───────────────────────────────
//
// s_inode_cache: populated during kubepods walks and parent-dir scans.
// s_pod_parent_cache: pod UID → cgroup parent directory (pod slice).  When a
// second container in the same pod is born, try_parent_scan() lists only that
// directory's children — O(containers-in-pod) instead of O(all cgroups).
//
// Thread safety: resolve() may run from multiple std::threads (async birth
// workers in main.cpp); all cache access is guarded by s_cache_mu.
//
// Future: fanotify on kubepods for incremental directory creation (retro TODO).

static std::mutex s_cache_mu;
static std::unordered_map<uint64_t, fs::path> s_inode_cache;
static std::unordered_map<std::string, fs::path> s_pod_parent_cache;

/* S2.1 — cgroup_mkdir → inode catalog (bounded; FIFO evict under burst). */
static std::mutex                                  s_cat_mu;
static uint64_t                                    s_mkdir_events_total = 0;
static std::unordered_map<uint64_t, std::uint32_t> s_cgroup_event_hits;
static std::deque<uint64_t>                        s_cgroup_fifo;
static std::unordered_map<uint64_t, uint64_t>      s_cgroup_birth_ns;

static void record_cgroup_mkdir_impl(uint64_t cgroup_inode,
                                     uint64_t birth_monotonic_ns)
{
    constexpr size_t k_max = KOTA_DEFAULT_STATUS_MAP_ENTRIES;

    std::lock_guard<std::mutex> lock(s_cat_mu);
    ++s_mkdir_events_total;
    auto hit = s_cgroup_event_hits.find(cgroup_inode);
    if (hit != s_cgroup_event_hits.end()) {
        ++hit->second;
        if (birth_monotonic_ns != 0u)
            s_cgroup_birth_ns[cgroup_inode] = birth_monotonic_ns;
    } else {
        while (s_cgroup_event_hits.size() >= k_max && !s_cgroup_fifo.empty()) {
            const uint64_t ev = s_cgroup_fifo.front();
            s_cgroup_fifo.pop_front();
            s_cgroup_event_hits.erase(ev);
            s_cgroup_birth_ns.erase(ev);
        }
        s_cgroup_fifo.push_back(cgroup_inode);
        s_cgroup_event_hits.emplace(cgroup_inode, 1u);
        if (birth_monotonic_ns != 0u)
            s_cgroup_birth_ns[cgroup_inode] = birth_monotonic_ns;
    }

    if (const char *e = std::getenv("KOTA_LOG_CGROUP_CATALOG"); e != nullptr &&
        (e[0] == '1' || e[0] == 't' || e[0] == 'T')) {
        std::cerr << "[KOTA] cgroup catalog: inode=" << cgroup_inode
                  << " birth_ns=" << birth_monotonic_ns
                  << " total_events=" << s_mkdir_events_total
                  << " unique=" << s_cgroup_event_hits.size() << '\n';
    }
}

/*
 * Locate the kubepods subtree root (varies by cgroup driver).
 *   systemd : /sys/fs/cgroup/kubepods.slice
 *   cgroupfs: /sys/fs/cgroup/kubepods
 * Cached after the first discovery.
 */
static fs::path s_kubepods_root;

static const fs::path &kubepods_root()
{
    if (!s_kubepods_root.empty())
        return s_kubepods_root;

    constexpr auto cgroup_root = "/sys/fs/cgroup";
    std::error_code ec;
    for (const auto &entry : fs::directory_iterator(cgroup_root, ec)) {
        if (entry.is_directory() &&
            entry.path().filename().string().starts_with("kubepods")) {
            s_kubepods_root = entry.path();
            return s_kubepods_root;
        }
    }
    return s_kubepods_root;
}

/*
 * Second container in same pod: list children of cached pod slice parents only.
 */
static std::optional<fs::path> try_parent_scan(uint64_t inode)
{
    std::vector<fs::path> parents;
    {
        std::lock_guard<std::mutex> lock(s_cache_mu);
        parents.reserve(s_pod_parent_cache.size());
        for (const auto &kv : s_pod_parent_cache)
            parents.push_back(kv.second);
    }

    for (const auto &parent : parents) {
        std::error_code ec;
        for (const auto &entry :
             fs::directory_iterator(parent,
                                    fs::directory_options::skip_permission_denied,
                                    ec))
        {
            if (!entry.is_directory())
                continue;
            if (entry.path().string().size() > 4096)
                continue;
            struct stat st{};
            if (::stat(entry.path().c_str(), &st) != 0)
                continue;
            auto ino = static_cast<uint64_t>(st.st_ino);
            {
                std::lock_guard<std::mutex> lock(s_cache_mu);
                s_inode_cache.emplace(ino, entry.path());
                if (ino == inode)
                    return entry.path();
            }
        }
    }
    return std::nullopt;
}

/*
 * Resolve a kernfs inode → cgroup filesystem path.
 *
 * 1. O(1) cache lookup (under lock).
 * 2. Pod-parent scan: O(siblings) when a prior container in the same pod
 *    was already resolved (typical: pause + app container).
 * 3. Full kubepods recursive walk on miss; merge discovered inodes into cache.
 */
static std::expected<fs::path, std::string>
find_cgroup_path(uint64_t inode)
{
    {
        std::lock_guard<std::mutex> lock(s_cache_mu);
        if (auto it = s_inode_cache.find(inode); it != s_inode_cache.end())
            return it->second;
    }

    if (auto fast = try_parent_scan(inode))
        return *fast;

    const auto &root = kubepods_root();
    if (root.empty())
        return std::unexpected("skip:no kubepods subtree under /sys/fs/cgroup");

    std::unordered_map<uint64_t, fs::path> discovered;
    std::optional<fs::path> hit;
    std::error_code ec;
    for (const auto &entry :
         fs::recursive_directory_iterator(
             root, fs::directory_options::skip_permission_denied, ec))
    {
        if (!entry.is_directory())
            continue;
        if (entry.path().string().size() > 4096)
            continue;
        struct stat st{};
        if (::stat(entry.path().c_str(), &st) != 0)
            continue;
        auto ino = static_cast<uint64_t>(st.st_ino);
        discovered.emplace(ino, entry.path());
        if (ino == inode)
            hit = entry.path();
    }

    {
        std::lock_guard<std::mutex> lock(s_cache_mu);
        for (const auto &[ino, p] : discovered)
            s_inode_cache.emplace(ino, p);
        if (auto it = s_inode_cache.find(inode); it != s_inode_cache.end())
            return it->second;
    }

    return std::unexpected("skip:cgroup inode " + std::to_string(inode) +
                           " not found under kubepods");
}

/*
 * Extract the 64-hex-char container ID from the cgroup leaf directory name.
 * Supports containerd (cri-containerd-<CID>.scope), CRI-O (crio-<CID>.scope),
 * and cgroupfs driver (plain <CID> directory name).
 * Returns an error starting with "skip:" for non-container cgroups so the
 * caller can silently ignore pod-level / system cgroups.
 */
static bool is_64hex(std::string_view s)
{
    if (s.size() != 64)
        return false;
    for (unsigned char c : s) {
        if (!std::isxdigit(c))
            return false;
    }
    return true;
}

static std::expected<std::string, std::string>
parse_container_id(const fs::path &cgroup_path)
{
    const std::string leaf = cgroup_path.filename().string();
    constexpr size_t   k_max_leaf = 512;

    if (leaf.size() > k_max_leaf)
        return std::unexpected("skip:leaf too long");
    if (leaf.empty())
        return std::unexpected("skip:empty filename");

    constexpr std::string_view cd_prefix   = "cri-containerd-";
    constexpr std::string_view crio_prefix = "crio-";
    constexpr std::string_view scope_sfx   = ".scope";

    if (leaf.starts_with(cd_prefix) && leaf.ends_with(scope_sfx)) {
        const auto inner = std::string_view{leaf}.substr(
            cd_prefix.size(), leaf.size() - cd_prefix.size() - scope_sfx.size());
        if (!is_64hex(inner))
            return std::unexpected("skip:not-container:bad-containerd-id");
        return std::string{inner};
    }

    if (leaf.starts_with(crio_prefix) && leaf.ends_with(scope_sfx)) {
        const auto inner = std::string_view{leaf}.substr(
            crio_prefix.size(), leaf.size() - crio_prefix.size() - scope_sfx.size());
        if (!is_64hex(inner))
            return std::unexpected("skip:not-container:bad-crio-id");
        return std::string{inner};
    }

    if (leaf.size() == 64) {
        if (is_64hex(leaf))
            return leaf;
    }

    return std::unexpected("skip:not-container:" + leaf);
}

/*
 * Extract the pod UID from the cgroup path hierarchy.
 *   systemd driver : kubepods-burstable-pod<UID_UNDERSCORED>.slice
 *   cgroupfs driver: kubepods/burstable/pod<UID>
 * Underscores are normalized to dashes (standard UUID format).
 */
static std::expected<std::string, std::string>
parse_pod_uid(const fs::path &cgroup_path)
{
    const std::string path_str = cgroup_path.string();
    constexpr size_t  k_max_path = 4096;
    if (path_str.size() > k_max_path)
        return std::unexpected("skip:cgroup path too long for uid parse");

    auto pos = path_str.rfind("pod");
    if (pos == std::string::npos)
        return std::unexpected("pod UID not found in " + path_str);

    const auto     uid_start = pos + 3;
    if (uid_start >= path_str.size())
        return std::unexpected("skip:malformed pod prefix in path");
    const auto     uid_end   = path_str.find_first_of("./", uid_start);
    const size_t   uid_len =
        uid_end == std::string::npos ? path_str.size() - uid_start
                                     : uid_end - uid_start;
    if (uid_len > 128)
        return std::unexpected("skip:pod uid segment too long");
    if (uid_len < 4)
        return std::unexpected("skip:pod uid segment too short");

    std::string uid = path_str.substr(uid_start, uid_len);
    for (char &c : uid) {
        if (c == '_')
            c = '-';
    }

    if (uid.size() < 32)
        return std::unexpected("pod UID too short (" + uid + ") in " + path_str);
    if (uid.size() > 72)
        return std::unexpected("skip:pod uid implausible length");

    return uid;
}

static void record_pod_parent(const fs::path &cgroup_path)
{
    auto uid = parse_pod_uid(cgroup_path);
    if (!uid)
        return;
    std::lock_guard<std::mutex> lock(s_cache_mu);
    s_pod_parent_cache[*uid] = cgroup_path.parent_path();
}

/*
 * True if pid is in the initial (host) network namespace — same as PID 1.
 * Prefer /proc/1/ns/net over /proc/self: Sentinel may run in an unusual netns;
 * kube shims in cgroup.procs are almost always in init's netns while workload
 * PIDs are in the pod netns.
 */
static bool pid_shares_init_network(pid_t pid)
{
    struct stat st_pid {};
    struct stat st_init{};
    const std::string p = "/proc/" + std::to_string(pid) + "/ns/net";
    if (::stat(p.c_str(), &st_pid) != 0)
        return true; /* cannot inspect: try other PIDs / fall back */
    if (::stat("/proc/1/ns/net", &st_init) != 0)
        return false;
    return st_pid.st_ino == st_init.st_ino && st_pid.st_dev == st_init.st_dev;
}

static std::optional<uint64_t> read_netns_inode_for_pid(pid_t pid)
{
    struct stat st {};
    const std::string target_path = "/proc/" + std::to_string(pid) + "/ns/net";
    if (::stat(target_path.c_str(), &st) != 0)
        return std::nullopt;
    const uint64_t ino = static_cast<uint64_t>(st.st_ino);
    if (ino == 0)
        return std::nullopt;
    return ino;
}

/*
 * Read PIDs from cgroup.procs; prefer one that is **not** in the host netns.
 * The first line is often a host-side shim (host IP on eth0 / enp* when joined).
 */
static std::expected<pid_t, std::string>
read_cgroup_pid(const fs::path &cgroup_path)
{
    auto procs_path = cgroup_path / "cgroup.procs";

    auto try_read = [&]() -> pid_t {
        std::ifstream f(procs_path);
        if (!f.is_open())
            return -1;
        std::vector<pid_t> pids;
        pid_t pid = 0;
        while (f >> pid) {
            if (pid > 0)
                pids.push_back(pid);
        }
        if (pids.empty())
            return 0;
        for (pid_t c : pids) {
            if (!pid_shares_init_network(c))
                return c;
        }
        return 0; // force wait for non-init-net pid
    };

    /* Short spin only — if PID is not ready within ~512 reads, yield to µs sleeps. */
    constexpr int k_spin = 512;
    for (int i = 0; i < k_spin; ++i) {
        pid_t p = try_read();
        if (p < 0)
            return std::unexpected("cannot open " + procs_path.string());
        if (p > 0)
            { std::cerr << "[KOTA] read_cgroup_pid found non-init pid " << p << "\n"; return p; }
        if ((i & 0x3Fu) == 0)
            std::this_thread::yield();
    }

    constexpr int k_micro_rounds = 400;
    for (int i = 0; i < k_micro_rounds; ++i) {
        pid_t p = try_read();
        if (p < 0)
            return std::unexpected("cannot open " + procs_path.string());
        if (p > 0)
            { std::cerr << "[KOTA] read_cgroup_pid found non-init pid " << p << "\n"; return p; }
        std::this_thread::sleep_for(std::chrono::microseconds(50));
    }

    for (int i = 0; i < 8; ++i) {
        pid_t p = try_read();
        if (p < 0)
            return std::unexpected("cannot open " + procs_path.string());
        if (p > 0)
            { std::cerr << "[KOTA] read_cgroup_pid found non-init pid " << p << "\n"; return p; }
        std::this_thread::sleep_for(std::chrono::milliseconds(1 << i));
    }

    // Fallback: If we timed out waiting for an isolated PID, just grab whatever we can (e.g. hostNetwork pod/shim)
    std::ifstream ff(procs_path);
    pid_t fallback_pid = 0;
    if (ff >> fallback_pid && fallback_pid > 0) {
        std::cerr << "[KOTA] read_cgroup_pid yielding fallback (likely hostnet) PID " << fallback_pid << "\n";
        return fallback_pid;
    }
    return std::unexpected("no PID in " + procs_path.string());
}

/*
 * Primary: enter the pod's network namespace and read IPv4 on eth0.
 * This avoids fib_trie ordering bugs (Cilium host /32,
 * docker0 172.17.0.1, link-local) that break kota_ip_to_inode + CiliumPeeker.
 */
static std::optional<std::string> read_pod_ip_via_default_iface(pid_t pid)
{
    const std::string ifname = "eth0";

    const std::string target_path = "/proc/" + std::to_string(pid) + "/ns/net";
    std::lock_guard<std::mutex> net_guard(s_netns_ip_mu);

    int self_net = ::open("/proc/self/ns/net", O_RDONLY);
    if (self_net < 0)
        return std::nullopt;
    int target_net = ::open(target_path.c_str(), O_RDONLY);
    if (target_net < 0) {
        ::close(self_net);
        return std::nullopt;
    }
    if (::setns(target_net, CLONE_NEWNET) != 0) {
        ::close(target_net);
        ::close(self_net);
        return std::nullopt;
    }
    ::close(target_net);

    struct ifaddrs *ifs = nullptr;
    std::vector<std::string> addrs;
    if (::getifaddrs(&ifs) == 0) {
        for (struct ifaddrs *p = ifs; p != nullptr; p = p->ifa_next) {
            if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET || !p->ifa_name)
                continue;
            if (std::strcmp(ifname.c_str(), p->ifa_name) != 0)
                continue;
            const auto *sin =
                reinterpret_cast<const struct sockaddr_in *>(p->ifa_addr);
            char buf[INET_ADDRSTRLEN]{};
            if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) == nullptr)
                continue;
            if (std::strncmp(buf, "127.", 4) == 0)
                continue;
            addrs.emplace_back(buf);
        }
        ::freeifaddrs(ifs);
    }

    std::optional<std::string> out;
    if (!addrs.empty()) {
        /* Prefer RFC1918 pod CIDR (10/8) over 172.16/12 and node LAN 192.168/16. */
        for (const auto &s : addrs) {
            if (s.starts_with("10."))
                out = s;
        }
        if (!out) {
            for (const auto &s : addrs) {
                if (s.starts_with("172."))
                    out = s;
            }
        }
        if (!out)
            out = addrs.front();
    }

    if (::setns(self_net, CLONE_NEWNET) != 0) {
        ::close(self_net);
        return std::nullopt;
    }
    ::close(self_net);
    return out;
}

static bool ipv4_is_172_17(const std::string &ip)
{
    struct in_addr a{};
    if (::inet_pton(AF_INET, ip.c_str(), &a) != 1)
        return false;
    const uint32_t be = ntohl(a.s_addr);
    return (be >> 16) == (172u * 256u + 17u);
}

static bool ipv4_is_link_local_169(const std::string &ip)
{
    struct in_addr a{};
    if (::inet_pton(AF_INET, ip.c_str(), &a) != 1)
        return false;
    const uint32_t be = ntohl(a.s_addr);
    return (be >> 16) == (169u * 256u + 254u);
}

/* Lower is better when fib_trie lists several /32 host LOCAL (Cilium + pod). */
static int pod_primary_ip_rank(const std::string &ip)
{
    if (ip.starts_with("10."))
        return 0;
    struct in_addr a{};
    if (::inet_pton(AF_INET, ip.c_str(), &a) == 1) {
        const uint32_t be = ntohl(a.s_addr);
        const uint32_t hi = be >> 16;
        if (hi >= 0xac10u && hi <= 0xac1fu) /* 172.16.0.0 – 172.31.255.255 */
            return 1;
    }
    if (ip.starts_with("172."))
        return 2;
    if (ip.starts_with("192.168."))
        return 10;
    return 5;
}

/*
 * Tier-0 (no CRI / no netns): kubelet writes /var/lib/kubelet/pods/<uid>/etc-hosts
 * on the node. BPF sees cgroup_mkdir before kubelet finishes that file — we
 * micro-retry a few times (~5ms) then fall through to proc/netns (Tier-1b).
 * Override root: KOTA_KUBELET_PODS_ROOT. Disable: KOTA_DISABLE_KUBELET_ETC_HOSTS.
 */
static std::string kubelet_pods_root_from_env()
{
    const char *e = std::getenv("KOTA_KUBELET_PODS_ROOT");
    if (e && *e)
        return std::string{e};
    return std::string{"/var/lib/kubelet/pods"};
}

static std::string pod_uid_lowercase(std::string s)
{
    for (char &c : s)
        c = static_cast<char>(
            std::tolower(static_cast<unsigned char>(c)));
    return s;
}

static std::optional<std::string> first_column_ipv4(std::string_view line)
{
    std::size_t i = 0;
    while (i < line.size() &&
           std::isspace(static_cast<unsigned char>(line[i])))
        ++i;
    if (i >= line.size() || line[i] == '#')
        return std::nullopt;
    const std::size_t start = i;
    while (i < line.size() &&
           !std::isspace(static_cast<unsigned char>(line[i])))
        ++i;
    const std::string token(line.substr(start, i - start));
    struct in_addr a{};
    if (::inet_pton(AF_INET, token.c_str(), &a) != 1)
        return std::nullopt;
    char buf[INET_ADDRSTRLEN]{};
    if (::inet_ntop(AF_INET, &a, buf, sizeof(buf)) == nullptr)
        return std::nullopt;
    return std::string{buf};
}

static std::optional<std::string>
read_pod_ip_from_kubelet_etc_hosts_once(const std::string &pod_uid)
{
    const fs::path path = fs::path(kubelet_pods_root_from_env()) /
                          pod_uid_lowercase(pod_uid) / "etc-hosts";
    std::ifstream f(path);
    if (!f.is_open())
        return std::nullopt;
    std::vector<std::string> candidates;
    std::string line;
    while (std::getline(f, line)) {
        if (auto ip = first_column_ipv4(std::string_view{line})) {
            if (ip->starts_with("127."))
                continue;
            if (ipv4_is_link_local_169(*ip))
                continue;
            candidates.push_back(std::move(*ip));
        }
    }
    if (candidates.empty())
        return std::nullopt;
    return *std::min_element(candidates.begin(), candidates.end(),
                             [](const std::string &a, const std::string &b) {
                                 return pod_primary_ip_rank(a) <
                                        pod_primary_ip_rank(b);
                             });
}

/* Missing/empty etc-hosts vs cgroup_mkdir: bounded micro-retry, then caller
 * falls back to proc/netns (no in-tree CRI gRPC). */
static std::optional<std::string>
read_pod_ip_from_kubelet_etc_hosts(const std::string &pod_uid)
{
    constexpr int            k_attempts = 3;
    constexpr std::chrono::microseconds k_gap{2500};

    for (int attempt = 0; attempt < k_attempts; ++attempt) {
        if (auto ip = read_pod_ip_from_kubelet_etc_hosts_once(pod_uid))
            return ip;
        if (attempt + 1 < k_attempts)
            std::this_thread::sleep_for(k_gap);
    }
    return std::nullopt;
}

/*
 * Fallback: fib_trie /32 host LOCAL (see read_pod_ip_via_default_iface).
 */
static std::expected<std::string, std::string>
read_pod_ip_fib_trie(pid_t pid)
{
    auto path = "/proc/" + std::to_string(pid) + "/net/fib_trie";
    std::ifstream f(path);
    if (!f.is_open())
        return std::unexpected("cannot open " + path);

    std::vector<std::string> locals;
    std::string line, prev;
    while (std::getline(f, line)) {
        if (line.find("/32 host LOCAL") != std::string::npos && !prev.empty()) {
            auto ip_start = prev.find_first_of("0123456789");
            if (ip_start == std::string::npos) {
                prev = line;
                continue;
            }
            auto ip_end = prev.find('/', ip_start);
            if (ip_end == std::string::npos)
                ip_end = prev.find_first_of(" \t", ip_start);
            if (ip_end == std::string::npos)
                ip_end = prev.size();

            std::string ip = prev.substr(ip_start, ip_end - ip_start);
            if (ip.starts_with("127."))
                continue;
            if (ipv4_is_link_local_169(ip) || ipv4_is_172_17(ip))
                continue;
            locals.push_back(std::move(ip));
        }
        prev = line;
    }

    if (locals.empty())
        return std::unexpected("no pod IP in " + path);

    return *std::min_element(locals.begin(), locals.end(),
                             [](const std::string &a, const std::string &b) {
                                 return pod_primary_ip_rank(a) <
                                        pod_primary_ip_rank(b);
                             });
}

static std::expected<std::string, std::string>
read_pod_ip(pid_t pid)
{
    if (auto ip = read_pod_ip_via_default_iface(pid))
        return *ip;
    return read_pod_ip_fib_trie(pid);
}

/*
 * Read pod name + namespace from the container runtime state on disk.
 *
 * Strategy 1: containerd OCI config.json annotations
 *   Path: /run/containerd/io.containerd.runtime.v2.task/k8s.io/<CID>/config.json
 *   Keys: io.kubernetes.cri.sandbox-name, io.kubernetes.cri.sandbox-namespace
 *
 * Strategy 2: /proc/<pid>/root/etc/hostname → pod name
 *
 * Strategy 3: serviceaccount namespace file → namespace
 */
struct RuntimeMeta {
    std::string pod_name;
    std::string ns;
    std::string profile_label; /* OCI Labels key kota.ai/profile */
};

static constexpr size_t k_oci_config_max_bytes = 1024U * 1024U;

/* Bounded read: fuzz- / abuse-resistant against huge runtime state files. */
static bool read_oci_file_bounded(const std::string &path, std::string &out)
{
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open())
        return false;
    f.seekg(0, std::ios::end);
    const std::streamoff end = f.tellg();
    if (end < 0)
        return false;
    if (static_cast<size_t>(end) > k_oci_config_max_bytes)
        return false;
    f.seekg(0, std::ios::beg);
    if (end == 0)
        return false;
    out.clear();
    out.reserve(static_cast<size_t>(end) + 1u);
    out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return true;
}

static std::string extract_json_string(const std::string &blob,
                                       const std::string &key)
{
    auto kpos = blob.find("\"" + key + "\"");
    if (kpos == std::string::npos) return {};
    auto colon = blob.find(':', kpos + key.size() + 2);
    if (colon == std::string::npos) return {};
    auto qopen = blob.find('"', colon + 1);
    if (qopen == std::string::npos) return {};
    auto qclose = blob.find('"', qopen + 1);
    if (qclose == std::string::npos) return {};
    return blob.substr(qopen + 1, qclose - qopen - 1);
}

static std::string read_trimmed_line(const std::string &path)
{
    std::ifstream f(path);
    std::string line;
    if (f.is_open() && std::getline(f, line)) {
        while (!line.empty() && std::isspace(static_cast<unsigned char>(line.back())))
            line.pop_back();
    }
    return line;
}

/* Fill RuntimeMeta from OCI JSON (any subset; proc fallbacks may complete). */
static void parse_oci_config_blob(const std::string &blob, RuntimeMeta &meta)
{
    meta.pod_name   = extract_json_string(blob, "io.kubernetes.cri.sandbox-name");
    meta.ns         = extract_json_string(blob, "io.kubernetes.cri.sandbox-namespace");
    if (meta.pod_name.empty())
        meta.pod_name = extract_json_string(blob, "hostname");
    meta.profile_label = extract_json_string(blob, "kota.ai/profile");
}

/*
 * unshare(CLONE_NEWNS) leaves the thread in a private mnt namespace; we must
 * setns(2) back to the original before returning so resolve workers keep a
 * normal view of the host (open("/run/..."), /proc, etc.).
 */
struct MntNamespaceRestorer {
    int mnt_fd_;

    explicit MntNamespaceRestorer(int fd) : mnt_fd_(fd) {}
    ~MntNamespaceRestorer()
    {
        if (mnt_fd_ >= 0) {
            (void)::setns(mnt_fd_, CLONE_NEWNS);
            ::close(mnt_fd_);
        }
    }
    MntNamespaceRestorer(const MntNamespaceRestorer &) = delete;
    MntNamespaceRestorer &operator=(const MntNamespaceRestorer &) = delete;
};

/*
 * Host-side veth name (root netns) from pod netns: read `iflink` on a veth-like
 * interface (iflink != ifindex). CNI may use eth0, ens*, net1, etc. — not only eth0.
 * Cilium’s host leg is expected to be named `lxc*`.
 */

static std::expected<std::string, std::string>
host_veth_ifname_for_pid(pid_t pid)
{
    std::lock_guard<std::mutex> net_guard(s_netns_ip_mu);

    int self_net = ::open("/proc/self/ns/net", O_RDONLY);
    if (self_net < 0)
        return std::unexpected(std::string("open /proc/self/ns/net: ") +
                               std::strerror(errno));

    const std::string target_path = "/proc/" + std::to_string(pid) + "/ns/net";
    int target_net = ::open(target_path.c_str(), O_RDONLY);
    if (target_net < 0) {
        ::close(self_net);
        return std::unexpected("open " + target_path + ": " +
                               std::strerror(errno));
    }

    int self_mnt = ::open("/proc/self/ns/mnt", O_RDONLY);
    if (self_mnt < 0) {
        ::close(target_net);
        ::close(self_net);
        return std::unexpected(std::string("open /proc/self/ns/mnt: ") +
                               std::strerror(errno));
    }

    if (::unshare(CLONE_NEWNS) != 0) {
        ::close(self_mnt);
        ::close(target_net);
        ::close(self_net);
        return std::unexpected(std::string("unshare CLONE_NEWNS: ") +
                               std::strerror(errno));
    }

    MntNamespaceRestorer mnt_scope{self_mnt};

    if (::setns(target_net, CLONE_NEWNET) != 0) {
        ::close(target_net);
        ::close(self_net);
        return std::unexpected(std::string("setns pod net: ") +
                               std::strerror(errno));
    }
    ::close(target_net);

    char tpl[] = "/tmp/kota_sys_tmp_XXXXXX";
    if (!::mkdtemp(tpl)) {
        if (::setns(self_net, CLONE_NEWNET) != 0) {}
        ::close(self_net);
        return std::unexpected(std::string("mkdtemp: ") + std::strerror(errno));
    }

    if (::mount("sysfs", tpl, "sysfs", MS_NOEXEC | MS_NOSUID | MS_NODEV, nullptr) != 0) {
        ::rmdir(tpl);
        if (::setns(self_net, CLONE_NEWNET) != 0) {}
        ::close(self_net);
        return std::unexpected(std::string("mount sysfs: ") + std::strerror(errno));
    }

    unsigned iflink = 0;
    std::string iflink_path = std::string(tpl) + "/class/net/eth0/iflink";

    // 40 attempts x 50ms = 2.0s maximum wait for CNI to inject eth0 into the namespace
    for (int attempts = 0; attempts < 40; ++attempts) {
        std::ifstream fl(iflink_path);
        if (fl >> iflink && iflink != 0) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    ::umount2(tpl, MNT_DETACH);
    ::rmdir(tpl);

    if (iflink == 0) {
        if (::setns(self_net, CLONE_NEWNET) != 0) {}
        ::close(self_net);
        return std::unexpected("could not read eth0/iflink directly from netns sysfs");
    }

    int host_net = ::open("/proc/1/ns/net", O_RDONLY);
    if (host_net < 0) {
        if (::setns(self_net, CLONE_NEWNET) != 0) {}
        ::close(self_net);
        return std::unexpected("open /proc/1/ns/net: " + std::string(std::strerror(errno)));
    }

    if (::setns(host_net, CLONE_NEWNET) != 0) {
        ::close(host_net);
        if (::setns(self_net, CLONE_NEWNET) != 0) {}
        ::close(self_net);
        return std::unexpected("setns host net: " + std::string(std::strerror(errno)));
    }
    ::close(host_net);

    char name[IF_NAMESIZE]{};
    if (!if_indextoname(iflink, name)) {
        if (::setns(self_net, CLONE_NEWNET) != 0) {}
        ::close(self_net);
        return std::unexpected("if_indextoname(" + std::to_string(iflink) +
                               "): " + std::string(std::strerror(errno)));
    }

    if (::setns(self_net, CLONE_NEWNET) != 0) {
        ::close(self_net);
        return std::unexpected(std::string("setns restore: ") +
                               std::strerror(errno));
    }
    ::close(self_net);

    if (std::strncmp(name, "lxc", 3) != 0) {
        std::cerr
            << "[KOTA] PodResolver: host veth `" << name
            << "` is not a Cilium lxc* name — check CNI / TCX attach target\n";
    }

    return std::string(name);
}

static uint64_t inode_of_file(const fs::path &p)
{
    struct stat st{};
    if (::stat(p.c_str(), &st) != 0)
        return 0;
    return static_cast<uint64_t>(st.st_ino);
}

/*
 * When cgroup_mkdir fires on a pod slice (not a container leaf), walk one or two
 * levels for cri-containerd-*.scope / crio-*.scope / cgroupfs hex IDs (S4.1).
 */
static std::optional<fs::path> find_container_leaf_dir_under(const fs::path &root)
{
    std::error_code ec;
    for (const auto &entry : fs::directory_iterator(
             root, fs::directory_options::skip_permission_denied, ec))
    {
        if (!entry.is_directory())
            continue;
        if (parse_container_id(entry.path()).has_value())
            return entry.path();
    }
    for (const auto &entry : fs::directory_iterator(
             root, fs::directory_options::skip_permission_denied, ec))
    {
        if (!entry.is_directory())
            continue;
        std::error_code ec2;
        for (const auto &sub : fs::directory_iterator(
                 entry.path(),
                 fs::directory_options::skip_permission_denied, ec2))
        {
            if (!sub.is_directory())
                continue;
            if (parse_container_id(sub.path()).has_value())
                return sub.path();
        }
    }
    return std::nullopt;
}

static RuntimeMeta read_runtime_meta(const std::string &container_id, pid_t pid)
{
    RuntimeMeta meta;
    constexpr std::string_view task_suffix =
        "/io.containerd.runtime.v2.task/k8s.io/";

    /* Try known containerd state directories:
     *   vanilla containerd : /run/containerd/...
     *   k3s               : /run/k3s/containerd/...
     *   k0s               : /run/k0s/containerd/...
     *   rke2              : /run/rke2/containerd/...  */
    for (const char *prefix : {"/run/containerd",
                               "/run/k3s/containerd",
                               "/run/k0s/containerd",
                               "/run/rke2/containerd"}) {
        const std::string path = std::string(prefix) + std::string(task_suffix) +
                                 container_id + "/config.json";
        std::string       blob;
        if (read_oci_file_bounded(path, blob)) {
            parse_oci_config_blob(blob, meta);
            break; /* use first on-disk OCI file found */
        }
    }

    if (meta.pod_name.empty())
        meta.pod_name = read_trimmed_line(
            "/proc/" + std::to_string(pid) + "/root/etc/hostname");

    if (meta.ns.empty())
        meta.ns = read_trimmed_line(
            "/proc/" + std::to_string(pid) +
            "/root/var/run/secrets/kubernetes.io/serviceaccount/namespace");

    if (meta.pod_name.empty()) meta.pod_name = "unknown";
    if (meta.ns.empty())       meta.ns       = "unknown";
    return meta;
}

// ── PodResolver public API ──────────────────────────────────────────────────

PodResolver::PodResolver(int status_map_fd, int ip_to_inode_map_fd,
                           int cgroup_bridge_map_fd, int netns_status_map_fd,
                           std::string cri_socket, ProfileRegistry *profile_registry)
    : status_map_fd_(status_map_fd)
    , ip_to_inode_map_fd_(ip_to_inode_map_fd)
    , cgroup_bridge_map_fd_(cgroup_bridge_map_fd)
    , netns_status_map_fd_(netns_status_map_fd)
    , cri_socket_(std::move(cri_socket))
    , cilium_socket_path_("/var/run/cilium/cilium.sock")
    , profile_registry_(profile_registry)
{
    if (const char *e = std::getenv("KOTA_CILIUM_SOCKET"); e != nullptr && e[0] != '\0')
        cilium_socket_path_ = e;
    if (std::getenv("KOTA_DISABLE_CILIUM_API") == nullptr)
        identity_backends_.push_back(
            std::make_unique<CiliumUdsIdentityBackend>(cilium_socket_path_));
    identity_backends_.push_back(std::make_unique<OciProcIdentityBackend>());
}

PodResolver::~PodResolver() = default;

CiliumUdsIdentityBackend::CiliumUdsIdentityBackend(std::string agent_socket_path)
    : agent_socket_path_{std::move(agent_socket_path)}
{}

const char *CiliumUdsIdentityBackend::layer_label() const noexcept
{
    return "Cilium-UDS";
}

const char *OciProcIdentityBackend::layer_label() const noexcept
{
    return "OCI-proc";
}

/*
 * Hybrid note (future): GET /v1/endpoint/{id} uses Cilium's *local endpoint id* (top-level
 * JSON "id", e.g. 893), not the ipcache *security identity* (e.g. status.identity.id 20695).
 * CiliumPeeker today maps pod IP → sec_id only. A targeted UDS fetch needs IP/container →
 * local endpoint id via another pinned map or a filtered API before we can drop full-list
 * JSON parsing on large nodes.
 */

std::expected<std::optional<PodMeta>, std::string> CiliumUdsIdentityBackend::try_resolve(
    PodResolver &resolver, const fs::path &work_path, const std::string &container_id,
    uint64_t cgroup_inode)
{
    const auto try_uds = [&](bool bypass_cache) {
        return cilium_find_endpoint_by_container_id(agent_socket_path_, container_id,
                                                    bypass_cache);
    };
    std::error_code ec;
    if (!fs::is_socket(agent_socket_path_, ec)) {
        static std::atomic<bool> s_warned_no_cilium_sock{false};
        if (!s_warned_no_cilium_sock.exchange(true)) {
            std::cerr
                << "[KOTA] PodResolver: no Cilium agent socket at " << agent_socket_path_
                << " (only OCI/proc; set KOTA_CILIUM_SOCKET if the API listener is elsewhere)\n";
        }
        return std::optional<PodMeta>{std::nullopt};
    }

    using clock = std::chrono::steady_clock;
    const auto t_cilium0 = clock::now();
    auto         ce        = try_uds(false);
    const auto   t_after1  = clock::now();
    const auto   us_try1 =
        std::chrono::duration_cast<std::chrono::microseconds>(t_after1 - t_cilium0).count();

    if (ce) {
        if (ce->has_value()) {
            std::cout
                << "[KOTA] PodResolver: identity source=Cilium-UDS (container "
                << std::string_view{container_id.data(), 12} << "…)\n";
            if (resolve_timing_enabled()) {
                std::cerr << "[KOTA] PodResolver: timing Cilium-UDS try1=" << us_try1
                          << "µs (match on first pass)\n";
            }
            auto m = resolver.resolve_from_cilium_api(work_path, cgroup_inode, **ce);
            if (!m)
                return std::unexpected(m.error());
            return std::optional<PodMeta>{std::move(*m)};
        }
        /* Refetch with cache bypass. For sleep_ms>=2, split wait + UDS in the middle so we
         * can succeed as soon as Cilium publishes (same total sleep as one block; fewer
         * blind tail waits). docs/tasks/feedback.md — lighter than full Cilium monitor. */
        const auto t_sleep0 = clock::now();
        const int  sleep_ms = cilium_uds_retry_sleep_ms();

        if (sleep_ms >= 2) {
            const int first_ms = sleep_ms / 2;
            const int rem_ms   = sleep_ms - first_ms;
            std::this_thread::sleep_for(std::chrono::milliseconds(first_ms));
            const auto t_mid0 = clock::now();
            auto       cm     = try_uds(true);
            const auto t_mid1 = clock::now();
            if (resolve_timing_enabled()) {
                const long sl1 = std::chrono::duration_cast<std::chrono::microseconds>(t_mid0 - t_sleep0)
                                     .count();
                const long tmid =
                    std::chrono::duration_cast<std::chrono::microseconds>(t_mid1 - t_mid0).count();
                std::cerr << "[KOTA] PodResolver: timing Cilium-UDS try1=" << us_try1 << "µs sleep1="
                          << sl1 << "µs try_mid=" << tmid << "µs";
            }
            if (cm && cm->has_value()) {
                if (resolve_timing_enabled())
                    std::cerr << " (match mid-window)\n";
                std::cout
                    << "[KOTA] PodResolver: identity source=Cilium-UDS (mid-retry, container "
                    << std::string_view{container_id.data(), 12} << "…)\n";
                auto m_mid = resolver.resolve_from_cilium_api(work_path, cgroup_inode, **cm);
                if (!m_mid)
                    return std::unexpected(m_mid.error());
                return std::optional<PodMeta>{std::move(*m_mid)};
            }
            if (resolve_timing_enabled())
                std::cerr << '\n';
            if (rem_ms > 0)
                std::this_thread::sleep_for(std::chrono::milliseconds(rem_ms));
            const auto t_b2 = clock::now();
            auto       ce2  = try_uds(true);
            const auto t_e2 = clock::now();
            if (resolve_timing_enabled()) {
                const long sl2 =
                    std::chrono::duration_cast<std::chrono::microseconds>(t_b2 - t_mid1).count();
                const long tf =
                    std::chrono::duration_cast<std::chrono::microseconds>(t_e2 - t_b2).count();
                std::cerr << "[KOTA] PodResolver: timing Cilium-UDS sleep2=" << sl2 << "µs try_final="
                          << tf << "µs (split " << sleep_ms << "ms retry)\n";
            }
            if (ce2) {
                if (ce2->has_value()) {
                    std::cout
                        << "[KOTA] PodResolver: identity source=Cilium-UDS (2nd try, container "
                        << std::string_view{container_id.data(), 12} << "…)\n";
                    auto m2 = resolver.resolve_from_cilium_api(work_path, cgroup_inode, **ce2);
                    if (!m2)
                        return std::unexpected(m2.error());
                    return std::optional<PodMeta>{std::move(*m2)};
                }
            } else {
                std::cerr << "[KOTA] PodResolver: Cilium API: " << ce2.error()
                          << " (UDS retry window; OCI/proc fallback)\n";
            }
        } else {
            if (sleep_ms == 1)
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            const auto t_sl = clock::now();
            auto       ce2  = try_uds(true);
            const auto t_e2 = clock::now();
            if (resolve_timing_enabled()) {
                const long us_sl =
                    std::chrono::duration_cast<std::chrono::microseconds>(t_sl - t_sleep0).count();
                const long us_t2 =
                    std::chrono::duration_cast<std::chrono::microseconds>(t_e2 - t_sl).count();
                std::cerr << "[KOTA] PodResolver: timing Cilium-UDS try1=" << us_try1 << "µs sleep="
                          << us_sl << "µs try2(refetch)=" << us_t2
                          << "µs (try2 bypasses cache → full HTTP+JSON)\n";
            }
            if (ce2) {
                if (ce2->has_value()) {
                    std::cout
                        << "[KOTA] PodResolver: identity source=Cilium-UDS (2nd try, container "
                        << std::string_view{container_id.data(), 12} << "…)\n";
                    auto m2 = resolver.resolve_from_cilium_api(work_path, cgroup_inode, **ce2);
                    if (!m2)
                        return std::unexpected(m2.error());
                    return std::optional<PodMeta>{std::move(*m2)};
                }
            } else {
                std::cerr << "[KOTA] PodResolver: Cilium API: " << ce2.error()
                          << " (UDS retry window; OCI/proc fallback)\n";
            }
        }

        std::cerr
            << "[KOTA] PodResolver: Cilium /v1/endpoint: no match for container id after "
               "retry window (using OCI/proc; UDS can race the workload or list may be"
               " large)\n";
    } else {
        std::cerr << "[KOTA] PodResolver: Cilium API: " << ce.error()
                  << " (using OCI/proc fallback)\n";
        if (resolve_timing_enabled()) {
            std::cerr << "[KOTA] PodResolver: timing Cilium-UDS try1=" << us_try1
                      << "µs (HTTP/JSON or transport error)\n";
        }
    }
    return std::optional<PodMeta>{std::nullopt};
}

std::expected<std::optional<PodMeta>, std::string> OciProcIdentityBackend::try_resolve(
    PodResolver &resolver, const fs::path &work_path, const std::string &container_id,
    uint64_t cgroup_inode)
{
    using clock = std::chrono::steady_clock;
    const auto t0 = clock::now();
    auto       pid = read_cgroup_pid(work_path);
    const auto t1 = clock::now();
    if (!pid)
        return std::unexpected(pid.error());
    std::cout
        << "[KOTA] PodResolver: identity source=OCI-proc (setns / runtime state / host veth)\n";
    auto m = resolver.resolve_via_oci_and_proc(work_path, container_id, *pid, cgroup_inode);
    const auto t2 = clock::now();
    if (resolve_timing_enabled()) {
        const auto us_pid =
            std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
        const auto us_oci =
            std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
        std::cerr << "[KOTA] PodResolver: timing OCI-proc read_cgroup_pid=" << us_pid
                  << "µs resolve_via_oci_and_proc=" << us_oci << "µs\n";
    }
    if (!m)
        return std::unexpected(m.error());
    return std::optional<PodMeta>{std::move(*m)};
}

std::expected<PodMeta, std::string> PodResolver::resolve_from_cilium_api(
    const fs::path &work_path, uint64_t cgroup_inode, const CiliumEndpointFields &f)
{
    PodMeta meta{};
    meta.oci_profile_label = f.profile_label;
    if (f.profile_label.empty()) {
        return std::unexpected(
            "skip:profile-label-missing:cilium-endpoint has no kota.ai/profile");
    }
    meta.profile_id        = 0;
    if (profile_registry_ != nullptr) {
        if (auto id = profile_registry_->get_profile_id(f.profile_label))
            meta.profile_id = *id;
    }
    if (meta.profile_id == 0) {
        return std::unexpected("skip:profile-unregistered:" + f.profile_label);
    }

    uint64_t leaf_ino = inode_of_file(work_path);
    if (leaf_ino == 0)
        leaf_ino = cgroup_inode;

    meta.cgroup_inode         = cgroup_inode;
    meta.leaf_cgroup_inode   = leaf_ino;
    meta.pod_name              = f.pod_name;
    meta.namespace_name      = f.namespace_name;
    meta.pod_ip                = f.pod_ip;
    meta.cilium_id             = f.identity_id;
    if (auto pid = read_cgroup_pid(work_path))
        meta.netns_inode = read_netns_inode_for_pid(*pid).value_or(0);
    if (!f.host_veth_ifname.empty()) {
        meta.host_veth_ifname = f.host_veth_ifname;
        if (kota_on_host_veth_resolved != nullptr) {
            std::cout << "[KOTA] PodResolver: Cilium API host_veth_ifname=" << meta.host_veth_ifname
                      << " for cgroup_inode=" << meta.cgroup_inode << '\n';
            kota_on_host_veth_resolved(meta.cgroup_inode, meta.host_veth_ifname.c_str());
        }
        if (!meta.host_veth_ifname.starts_with("lxc")) {
            std::cerr
                << "[KOTA] PodResolver: host veth `" << meta.host_veth_ifname
                << "` is not a Cilium lxc* name — check CNI / TCX attach target\n";
        }
    } else {
        std::cerr
            << "[KOTA] PodResolver: Cilium API did not return interface-name (no per-pod TCX until available)\n";
    }
    std::cout << "[KOTA] PodResolver: Cilium resolved pod="
              << meta.namespace_name << "/" << meta.pod_name
              << " ip=" << meta.pod_ip
              << " iface=" << (meta.host_veth_ifname.empty() ? "n/a" : meta.host_veth_ifname)
              << " cilium_id=" << meta.cilium_id
              << " profile=" << (meta.oci_profile_label.empty() ? "<missing>" : meta.oci_profile_label)
              << '\n';
    record_pod_parent(work_path);
    return meta;
}

std::expected<PodMeta, std::string> PodResolver::resolve_via_oci_and_proc(
    const fs::path &work_path, const std::string &cid, pid_t pid, uint64_t cgroup_inode)
{
    std::optional<std::string> kube_ip;
    if (!std::getenv("KOTA_DISABLE_KUBELET_ETC_HOSTS")) {
        if (auto pu = parse_pod_uid(work_path))
            kube_ip = read_pod_ip_from_kubelet_etc_hosts(*pu);
    }

    std::expected<std::string, std::string> ip =
        (kube_ip.has_value() && !kube_ip->empty())
            ? std::expected<std::string, std::string>{*kube_ip}
            : read_pod_ip(pid);
    if (!ip)
        return std::unexpected(ip.error());

    auto rmeta = read_runtime_meta(cid, pid);

    PodMeta meta{};
    meta.oci_profile_label  = rmeta.profile_label;
    if (rmeta.profile_label.empty()) {
        return std::unexpected(
            "skip:profile-label-missing:oci runtime metadata has no kota.ai/profile");
    }
    meta.profile_id         = 0;
    if (profile_registry_ != nullptr) {
        if (auto id = profile_registry_->get_profile_id(rmeta.profile_label))
            meta.profile_id = *id;
    }
    if (meta.profile_id == 0) {
        return std::unexpected("skip:profile-unregistered:" + rmeta.profile_label);
    }

    uint64_t leaf_ino = inode_of_file(work_path);
    if (leaf_ino == 0)
        leaf_ino = cgroup_inode;

    meta.cgroup_inode      = cgroup_inode;
    meta.leaf_cgroup_inode = leaf_ino;
    meta.pod_name          = std::move(rmeta.pod_name);
    meta.namespace_name    = std::move(rmeta.ns);
    meta.pod_ip            = std::move(*ip);
    meta.netns_inode       = read_netns_inode_for_pid(pid).value_or(0);
    std::expected<std::string, std::string> hv = host_veth_ifname_for_pid(pid);
    for (int retry = 0; !hv && retry < 15; ++retry) {
        if (hv.error().find("No such file or directory") != std::string::npos ||
            hv.error().find("open /proc") != std::string::npos) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            if (auto new_pid = read_cgroup_pid(work_path)) {
                hv = host_veth_ifname_for_pid(*new_pid);
            }
        } else {
            break;
        }
    }

    if (hv) {
        meta.host_veth_ifname = std::move(*hv);
        if (kota_on_host_veth_resolved != nullptr) {
            std::cout << "[KOTA] PodResolver: callback host_veth_ifname=" << meta.host_veth_ifname
                      << " for cgroup_inode=" << meta.cgroup_inode << '\n';
            kota_on_host_veth_resolved(meta.cgroup_inode, meta.host_veth_ifname.c_str());
        }
    } else {
        std::cerr << "[KOTA] PodResolver: host_veth_ifname unavailable: " << hv.error()
                  << " (no per-pod TCX until fixed)\n";
    }
    record_pod_parent(work_path);
    return meta;
}

std::expected<PodMeta, std::string> PodResolver::resolve(uint64_t cgroup_inode)
{
    using clock = std::chrono::steady_clock;
    const auto  t_resolve0 = clock::now();
    const bool  log_phases = resolve_timing_enabled();

    uint64_t birth_from_map = 0;
    if (status_map_fd_ >= 0) {
        struct kota_status_map_value st{};
        if (bpf_map_lookup_elem(status_map_fd_, &cgroup_inode, &st) == 0)
            birth_from_map = st.birth_ns;
    }
    on_cgroup_mkdir(cgroup_inode, birth_from_map);

    auto cgroup_path = find_cgroup_path(cgroup_inode);
    if (!cgroup_path)
        return std::unexpected(cgroup_path.error());

    /*
     * Runtime exec shims can create child cgroups under an already-managed pod
     * cgroup. Inherit parent status so LSM ioctl enforcement sees the same
     * profile/verdict for child tasks without requiring a fresh identity resolve.
     */
    if (status_map_fd_ >= 0) {
        for (fs::path parent = cgroup_path->parent_path();
             !parent.empty() && parent != parent.root_path();
             parent = parent.parent_path())
        {
            struct stat pst{};
            if (::stat(parent.c_str(), &pst) != 0)
                continue;
            const uint64_t parent_ino = static_cast<uint64_t>(pst.st_ino);
            if (parent_ino == 0 || parent_ino == cgroup_inode)
                continue;

            struct kota_status_map_value parent_st{};
            if (bpf_map_lookup_elem(status_map_fd_, &parent_ino, &parent_st) != 0)
                continue;
            if (parent_st.profile_id == 0)
                continue;

            MapUpdater updater(status_map_fd_, ip_to_inode_map_fd_);
            MapUpdater::StatusUpsert req{};
            req.inode = cgroup_inode;
            req.profile_id = parent_st.profile_id;
            req.cilium_id = parent_st.cilium_id;
            req.verdict = parent_st.verdict;
            if (auto r = updater.upsert_status(req); !r)
                return std::unexpected("child status inheritance failed: " + r.error());

            std::cout << "[KOTA] PodResolver: inherited status for child cgroup inode="
                      << cgroup_inode << " from parent inode=" << parent_ino
                      << " profile_id=" << parent_st.profile_id << '\n';
            return std::unexpected("skip:inherited-managed-child-cgroup");
        }
    }

    fs::path work_path = *cgroup_path;
    if (!parse_container_id(work_path).has_value()) {
        auto leaf_dir = find_container_leaf_dir_under(work_path);
        if (!leaf_dir)
            return std::unexpected("skip:not-container-under:" + cgroup_path->string());
        work_path = *leaf_dir;
    }

    auto cid = parse_container_id(work_path);
    if (!cid)
        return std::unexpected(cid.error());

    const auto t_layers0 = clock::now();
    if (log_phases) {
        const auto us_prefix =
            std::chrono::duration_cast<std::chrono::microseconds>(t_layers0 - t_resolve0)
                .count();
        std::cerr << "[KOTA] PodResolver: timing cgroup_prefix(catalog+find_path+container_id)="
                  << us_prefix << "µs\n";
    }

    for (auto &layer : identity_backends_) {
        const auto t_layer0 = clock::now();
        auto       out      = layer->try_resolve(*this, work_path, *cid, cgroup_inode);
        const auto t_layer1 = clock::now();
        if (log_phases) {
            const auto us_layer =
                std::chrono::duration_cast<std::chrono::microseconds>(t_layer1 - t_layer0)
                    .count();
            std::cerr << "[KOTA] PodResolver: timing layer " << layer->layer_label()
                      << " try_resolve=" << us_layer << "µs\n";
        }
        if (!out)
            return std::unexpected(out.error());
        if (out->has_value()) {
            if (log_phases) {
                const auto us_total =
                    std::chrono::duration_cast<std::chrono::microseconds>(t_layer1 - t_resolve0)
                        .count();
                std::cerr << "[KOTA] PodResolver: timing resolve_total=" << us_total
                          << "µs (set KOTA_LOG_RESOLVE_TIMING=0 to silence)\n";
            }
            return std::move(**out);
        }
    }
    if (log_phases) {
        const auto t_fail = clock::now();
        const auto us_total =
            std::chrono::duration_cast<std::chrono::microseconds>(t_fail - t_resolve0).count();
        std::cerr << "[KOTA] PodResolver: timing resolve_total=" << us_total
                  << "µs (no layer returned PodMeta)\n";
    }
    return std::unexpected("PodResolver: no identity layer returned PodMeta");
}

void PodResolver::on_cgroup_mkdir(uint64_t cgroup_inode,
                                  uint64_t birth_monotonic_ns)
{
    record_cgroup_mkdir_impl(cgroup_inode, birth_monotonic_ns);
}

uint64_t PodResolver::cgroup_mkdir_events_total() const noexcept
{
    std::lock_guard<std::mutex> lock(s_cat_mu);
    return s_mkdir_events_total;
}

uint64_t PodResolver::cgroup_catalog_unique_inodes() const noexcept
{
    std::lock_guard<std::mutex> lock(s_cat_mu);
    return static_cast<uint64_t>(s_cgroup_event_hits.size());
}

std::expected<void, std::string> PodResolver::enforce(const PodMeta &meta,
                                                       uint32_t profile_id)
{
    const uint64_t leaf = meta.leaf_cgroup_inode ? meta.leaf_cgroup_inode
                                                   : meta.cgroup_inode;
    MapUpdater updater(status_map_fd_, ip_to_inode_map_fd_, netns_status_map_fd_);

    MapUpdater::StatusUpsert req {};
    req.inode         = leaf;
    req.trigger_inode = (meta.cgroup_inode != leaf)
                          ? std::optional<uint64_t> {meta.cgroup_inode}
                          : std::nullopt;
    req.profile_id = profile_id;
    req.cilium_id  = meta.cilium_id;
    req.verdict    = KOTA_VERDICT_ACTIVE;

    if (auto r = updater.upsert_status(req); !r)
        return std::unexpected(r.error());

    if (auto r = updater.upsert_ip_to_inode(meta.pod_ip, leaf); !r)
        return std::unexpected(r.error());

    if (netns_status_map_fd_ >= 0 && meta.netns_inode != 0) {
        struct kota_status_map_value v{};
        if (bpf_map_lookup_elem(status_map_fd_, &leaf, &v) == 0) {
            if (bpf_map_update_elem(netns_status_map_fd_, &meta.netns_inode, &v, BPF_ANY) != 0) {
                return std::unexpected("NetnsStatus update failed for netns inode " +
                                       std::to_string(meta.netns_inode) + ": " +
                                       std::strerror(errno));
            }
        }
    }

    if (cgroup_bridge_map_fd_ >= 0) {
        const __u64 canonical = leaf;
        const __u64 leaf_key = leaf;
        (void)bpf_map_update_elem(cgroup_bridge_map_fd_, &leaf_key, &canonical, BPF_ANY);
        const __u64 trigger_key = meta.cgroup_inode;
        (void)bpf_map_update_elem(cgroup_bridge_map_fd_, &trigger_key, &canonical, BPF_ANY);
    }

    return {};
}

std::expected<void, std::string>
PodResolver::remove_ip_attribution(const std::string &pod_ip,
                                   [[maybe_unused]] uint64_t cgroup_inode)
{
    if (kota_on_cgroup_removed != nullptr)
        kota_on_cgroup_removed(cgroup_inode);

    MapUpdater updater(status_map_fd_, ip_to_inode_map_fd_);
    return updater.delete_ip_to_inode(pod_ip);
}

#if defined(KOTA_BUILD_POD_RESOLVER_PARSE_UNIT_TEST)
/*
 * Parse-only unit tests (same TU as production parsers). Built only as CMake
 * target `pod_resolver_parse_test` (see kota/CMakeLists.txt).
 */
bool run_pod_resolver_parse_unit_tests()
{
    const std::string hex64 =
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    const std::string bad64 =
        "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";

    auto fail = [](const char *m) {
        std::cerr << "[pod_resolver_parse] FAIL: " << m << '\n';
        return false;
    };

    {
        const auto p = parse_container_id(
            fs::path("cri-containerd-" + hex64 + ".scope"));
        if (!p || *p != hex64)
            return fail("cri-containerd .scope 64-hex");
    }
    {
        const auto p =
            parse_container_id(fs::path("crio-" + hex64 + ".scope"));
        if (!p || *p != hex64)
            return fail("crio .scope 64-hex");
    }
    {
        const auto p = parse_container_id(fs::path(hex64));
        if (!p || *p != hex64)
            return fail("cgroupfs 64-hex leaf");
    }
    {
        if (parse_container_id(fs::path("cri-containerd-" + bad64 + ".scope"))
                .has_value())
            return fail("reject non-hex in containerd id");
    }
    {
        std::string longleaf(600, 'a');
        if (parse_container_id(fs::path(longleaf)).has_value())
            return fail("reject oversize leaf");
    }
    {
        if (parse_container_id(fs::path("pause")).has_value())
            return fail("pause not a container id");
    }

    {
        const std::string cgfs =
            "/sys/fs/cgroup/kubepods/burstable/pod" +
            std::string("7e7f0e7e-5c6d-4b8a-9e1f-123456789abc") + "/x";
        const auto u = parse_pod_uid(fs::path(cgfs));
        if (!u || *u != "7e7f0e7e-5c6d-4b8a-9e1f-123456789abc")
            return fail("cgroupfs pod uid");
    }
    {
        const std::string sysd =
            "/sys/fs/cgroup/kubepods.slice/kubepods-burstable-pod" +
            std::string("7e7f0e7e_5c6d_4b8a_9e1f_123456789abc") + ".slice/leaf";
        const auto u = parse_pod_uid(fs::path(sysd));
        if (!u || *u != "7e7f0e7e-5c6d-4b8a-9e1f-123456789abc")
            return fail("systemd slice pod uid (underscores)");
    }
    {
        std::string longp(5000, '/');
        longp += "pod12345678";
        if (parse_pod_uid(fs::path(longp))
                .has_value()) // may fail with "not found" or "too long"
            return fail("path length guard");
    }
    {
        /* Under max path but uid segment < 32 (after "pod" prefix) */
        if (parse_pod_uid(fs::path("/cgroup/kubepods/pod" + std::string(20, 'a')))
                .has_value())
            return fail("short pod uid");
    }

    std::cout << "[pod_resolver_parse] OK\n";
    return true;
}
#endif

#if defined(KOTA_BUILD_POD_RESOLVER_OCI_PROFILE_GOLDEN_TEST)
/*
 * Golden: committed OCI `config.json` → kota.ai/profile string.
 * Built as CMake target `pod_resolver_oci_profile_golden_test`.
 */
bool run_pod_resolver_oci_profile_label_golden()
{
    auto fail = [](const char *m) {
        std::cerr << "[pod_resolver_oci_profile_golden] FAIL: " << m << '\n';
        return false;
    };

    std::string blob;
    if (!read_oci_file_bounded(KOTA_OCI_CONFIG_JSON_FIXTURE_PATH, blob))
        return fail("read committed config.json fixture");
    RuntimeMeta m{};
    parse_oci_config_blob(blob, m);
    if (m.profile_label != "Inference-Only")
        return fail("kota.ai/profile label (golden)");
    std::cout << "[pod_resolver_oci_profile_golden] OK (kota.ai/profile == "
                 "Inference-Only)\n";
    return true;
}
#endif

} // namespace kota

#if defined(KOTA_BUILD_POD_RESOLVER_PARSE_UNIT_TEST)
int main()
{
    return kota::run_pod_resolver_parse_unit_tests() ? 0 : 1;
}
#elif defined(KOTA_BUILD_POD_RESOLVER_OCI_PROFILE_GOLDEN_TEST)
int main()
{
    return kota::run_pod_resolver_oci_profile_label_golden() ? 0 : 1;
}
#endif
