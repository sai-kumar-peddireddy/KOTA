#include "cilium_peeker.h"

#include <bpf/bpf.h>
#include <arpa/inet.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>

namespace kota {

namespace {

constexpr uint8_t kCiliumEndpointKeyIPv4 = 1;

struct cilium_ipcache_key {
    uint32_t prefixlen;
    uint16_t cluster_id;
    uint8_t  pad1;
    uint8_t  family;
    uint8_t  ip[16];
} __attribute__((packed));

struct cilium_ipcache_value {
    uint32_t sec_identity;
    uint8_t  tunnel_endpoint[16];
    uint16_t _pad_node;
    uint8_t  tunnel_key;
    uint8_t  flags;
};

static_assert(sizeof(cilium_ipcache_value) == 24,
              "RemoteEndpointInfo must be 24 bytes for Cilium main");

} // namespace

static constexpr const char *kIpcachePinCandidates[] = {
    "/sys/fs/bpf/cilium/cilium_ipcache_v2",
    "/sys/fs/bpf/tc/globals/cilium_ipcache_v2",
    "/sys/fs/bpf/tc/globals/cilium_ipcache",
};

CiliumPeeker::CiliumPeeker() : available_(false)
{
    if (const char *override_path = std::getenv("KOTA_CILIUM_IPCACHE");
        override_path && *override_path)
    {
        ipcache_fd_ = bpf_obj_get(override_path);
        if (ipcache_fd_ >= 0) {
            available_ = true;
            ipcache_path_ = override_path;
            std::cout << "[KOTA] CiliumPeeker: ipcache from KOTA_CILIUM_IPCACHE fd="
                      << ipcache_fd_ << " path=" << override_path << '\n';
            return;
        }
        std::cerr << "[KOTA] CiliumPeeker: bpf_obj_get(" << override_path
                  << ") failed: " << std::strerror(errno) << '\n';
    }

    for (const char *path : kIpcachePinCandidates) {
        std::error_code ec;
        if (!std::filesystem::exists(path, ec) || ec)
            continue;
        ipcache_fd_ = bpf_obj_get(path);
        if (ipcache_fd_ >= 0) {
            available_ = true;
            ipcache_path_ = path;
            std::cout << "[KOTA] CiliumPeeker: ipcache fd=" << ipcache_fd_
                      << " path=" << path << '\n';
            return;
        }
        std::cerr << "[KOTA] CiliumPeeker: bpf_obj_get(" << path
                  << ") failed: " << std::strerror(errno) << '\n';
    }

    unavailable_reason_ =
        "no pinned cilium_ipcache map found (Tier 2 enrichment disabled)";
    std::cout << "[KOTA] CiliumPeeker: " << unavailable_reason_
              << " (set KOTA_CILIUM_IPCACHE if custom)\n";
}

bool CiliumPeeker::is_available() const { return available_; }

std::expected<uint32_t, std::string> CiliumPeeker::get_security_id(std::string_view pod_ip)
{
    if (!available_ || ipcache_fd_ < 0) {
        if (!logged_unavailable_reason_) {
            std::cout << "[KOTA] CiliumPeeker: no-op reason: "
                      << (unavailable_reason_.empty() ? "ipcache unavailable"
                                                      : unavailable_reason_)
                      << '\n';
            logged_unavailable_reason_ = true;
        }
        return 0u;
    }

    if (pod_ip.empty())
        return 0u;

    cilium_ipcache_key key{};
    std::memset(&key, 0, sizeof(key));
    key.prefixlen  = 64;
    key.cluster_id = 0;
    key.pad1       = 0;
    key.family     = kCiliumEndpointKeyIPv4;

    std::string ip_str(pod_ip);
    if (inet_pton(AF_INET, ip_str.c_str(), key.ip) != 1) {
        if (std::getenv("KOTA_CILIUM_DEBUG")) {
            std::cerr << "[KOTA] CiliumPeeker: invalid IPv4 pod_ip=" << pod_ip
                      << '\n';
        }
        return 0u;
    }

    cilium_ipcache_value val{};
    if (bpf_map_lookup_elem(ipcache_fd_, &key, &val) != 0) {
        if (!logged_lookup_miss_reason_) {
            std::cout << "[KOTA] CiliumPeeker: no-op reason: ipcache miss for pod IP "
                      << pod_ip << " (cilium_id=0, path="
                      << (ipcache_path_.empty() ? "unknown" : ipcache_path_)
                      << ")\n";
            logged_lookup_miss_reason_ = true;
        }
        if (std::getenv("KOTA_CILIUM_DEBUG"))
            std::cerr << "[KOTA] CiliumPeeker: lookup miss ip=" << pod_ip
                      << " errno=" << errno << '\n';
        return 0u;
    }

    const uint32_t sec_id = val.sec_identity;
    std::cout << "[KOTA] CiliumPeeker: " << pod_ip
              << " → security_id=" << sec_id << '\n';
    return sec_id;
}

} // namespace kota
