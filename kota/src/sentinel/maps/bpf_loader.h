#pragma once

/*
 * BpfLoader — loads CO-RE skeletons, resizes CE maps, pins StatusMap + IP_to_Inode.
 * See docs/tasks/sprints.md S1.1.
 */

#include <cstdint>
#include <expected>
#include <map>
#include <string>
#include <string_view>

struct bpf_link;

namespace kota {

struct BpfConfig {
    std::string bpffs_path           = "/sys/fs/bpf/kota";
    uint32_t    status_map_size      = 16384;
    uint32_t    profile_map_size     = 256;
    uint32_t    telemetry_size       = 16384;
    uint32_t    ip_to_inode_size     = 16384;
    uint32_t    ringbuf_size_bytes   = 16 * 1024 * 1024;
};

class BpfLoader {
public:
    explicit BpfLoader(BpfConfig cfg = {});
    ~BpfLoader();

    std::expected<void, std::string> load();
    void                             unload();

    int map_fd(std::string_view map_name) const;

    struct bpf_link *attach_ingress_tcx(const char *ifname) const;

    bool is_loaded() const { return loaded_; }

private:
    BpfConfig                  cfg_;
    bool                       loaded_ = false;
    std::map<std::string, int> map_fds_;
};

} // namespace kota
