#pragma once

#include <cstdint>
#include <expected>
#include <mutex>
#include <optional>
#include <string>

struct kota_status_map_value;

namespace kota {

/*
 * S3.2 MapUpdater
 *
 * Single-writer discipline:
 * - Callers should funnel pod birth/death map writes through one writer thread
 *   (resolver lifecycle hook path) to preserve deterministic update order.
 * - Internal locking still serializes writes to avoid interleaving when callers
 *   temporarily violate this discipline during bring-up.
 */
class MapUpdater {
public:
    struct StatusUpsert {
        uint64_t                inode = 0;
        std::optional<uint64_t> trigger_inode;
        uint32_t                profile_id = 0;
        uint32_t                cilium_id  = 0;
        uint32_t                verdict    = 0;
    };

    MapUpdater(int status_map_fd, int ip_to_inode_map_fd = -1,
               int netns_status_map_fd = -1);

    std::expected<void, std::string> upsert_status(const StatusUpsert &req);

    std::expected<void, std::string> upsert_ip_to_inode(const std::string &pod_ip,
                                                        uint64_t           inode);
    std::expected<void, std::string> delete_ip_to_inode(const std::string &pod_ip);

private:
    std::expected<kota_status_map_value, std::string>
    build_status_value(uint64_t inode, uint32_t profile_id, uint32_t cilium_id,
                       uint32_t verdict);

    int status_map_fd_;
    int ip_to_inode_map_fd_;
    int netns_status_map_fd_;

    std::mutex write_mu_;
};

} // namespace kota
