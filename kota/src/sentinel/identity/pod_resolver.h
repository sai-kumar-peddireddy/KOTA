#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <sys/types.h>
#include <vector>

namespace kota {

struct CiliumEndpointFields;

class ProfileRegistry;

struct PodMeta {
    uint64_t    cgroup_inode        = 0;
    uint64_t    leaf_cgroup_inode  = 0;
    std::string pod_name;
    std::string namespace_name;
    std::string pod_ip;
    std::string host_veth_ifname;
    uint32_t    cilium_id  = 0;
    uint64_t    netns_inode = 0;
    /**
     * Policy binding from OCI `kota.ai/profile` (empty = label absent).
     * profile_id is derived via ProfileRegistry (0 = unmanaged if unset or
     * unregistered name).
     */
    std::string oci_profile_label;
    uint32_t    profile_id = 0;
};

class PodResolver;

/**
 * Pluggable strategy for building PodMeta after the cgroup path and 64-hex
 * container id are known. Cilium-UDS may return std::nullopt to let the
 * OCI+proc path run; that layer is expected to return a filled PodMeta or an
 * error.
 */
class IPodIdentityBackend {
public:
    virtual ~IPodIdentityBackend() = default;
    /** Short name for KOTA_LOG_RESOLVE_TIMING summaries. */
    virtual const char *layer_label() const noexcept = 0;
    virtual std::expected<std::optional<PodMeta>, std::string> try_resolve(
        PodResolver &resolver, const std::filesystem::path &work_path,
        const std::string &container_id, uint64_t cgroup_inode) = 0;
};

class CiliumUdsIdentityBackend final : public IPodIdentityBackend {
public:
    explicit CiliumUdsIdentityBackend(std::string agent_socket_path);
    const char *layer_label() const noexcept override;
    std::expected<std::optional<PodMeta>, std::string> try_resolve(
        PodResolver &resolver, const std::filesystem::path &work_path,
        const std::string &container_id, uint64_t cgroup_inode) override;

private:
    std::string agent_socket_path_;
};

class OciProcIdentityBackend final : public IPodIdentityBackend {
public:
    const char *layer_label() const noexcept override;
    std::expected<std::optional<PodMeta>, std::string> try_resolve(
        PodResolver &resolver, const std::filesystem::path &work_path,
        const std::string &container_id, uint64_t cgroup_inode) override;
};

class PodResolver {
public:
    explicit PodResolver(
        int status_map_fd, int ip_to_inode_map_fd = -1,
        int cgroup_bridge_map_fd = -1,
        int netns_status_map_fd = -1,
        std::string cri_socket = "/run/containerd/containerd.sock",
        ProfileRegistry *profile_registry = nullptr);
    ~PodResolver();

    std::expected<PodMeta, std::string> resolve(uint64_t cgroup_inode);

    std::expected<void, std::string> enforce(const PodMeta &meta, uint32_t profile_id);

    std::expected<void, std::string> remove_ip_attribution(const std::string &pod_ip,
                                                            uint64_t cgroup_inode = 0);

    /** S2.1 — record tp_btf/cgroup_mkdir–driven work (see resolve() and ringbuf BIRTH). */
    void on_cgroup_mkdir(uint64_t cgroup_inode, uint64_t birth_monotonic_ns = 0);

    uint64_t cgroup_mkdir_events_total() const noexcept;
    uint64_t cgroup_catalog_unique_inodes() const noexcept;

private:
    int                status_map_fd_;
    int                ip_to_inode_map_fd_;
    int                cgroup_bridge_map_fd_;
    int                netns_status_map_fd_;
    std::string        cri_socket_;
    std::string        cilium_socket_path_;
    ProfileRegistry   *profile_registry_;
    std::vector<std::unique_ptr<IPodIdentityBackend>> identity_backends_;

    friend class CiliumUdsIdentityBackend;
    friend class OciProcIdentityBackend;

    std::expected<PodMeta, std::string>
    resolve_from_cilium_api(const std::filesystem::path &work_path, uint64_t cgroup_inode,
                            const CiliumEndpointFields &f);

    std::expected<PodMeta, std::string> resolve_via_oci_and_proc(
        const std::filesystem::path &work_path, const std::string &container_id, pid_t pid,
        uint64_t cgroup_inode);
};

} // namespace kota
