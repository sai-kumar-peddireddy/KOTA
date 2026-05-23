#include "map_updater.h"

#include "../../../include/shared/kota_common.h"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <time.h>

#include <cerrno>
#include <cstring>
#include <format>

namespace kota {

namespace {

std::expected<__u64, std::string> monotonic_now_ns()
{
    struct timespec ts {};
    if (::clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return std::unexpected(std::string("clock_gettime(CLOCK_MONOTONIC): ") +
                               std::strerror(errno));
    return static_cast<__u64>(ts.tv_sec) * 1000000000ull +
           static_cast<__u64>(ts.tv_nsec);
}

std::expected<__u64, std::string> boottime_now_ns()
{
    struct timespec ts {};
    if (::clock_gettime(CLOCK_BOOTTIME, &ts) != 0)
        return std::unexpected(std::string("clock_gettime(CLOCK_BOOTTIME): ") +
                               std::strerror(errno));
    return static_cast<__u64>(ts.tv_sec) * 1000000000ull +
           static_cast<__u64>(ts.tv_nsec);
}

std::expected<void, std::string> validate_verdict(uint32_t verdict)
{
    if (verdict != KOTA_VERDICT_ACTIVE && verdict != KOTA_VERDICT_VIOLATION) {
        return std::unexpected(
            std::format("invalid verdict {} (expected ACTIVE={} or VIOLATION={})",
                        verdict, static_cast<unsigned int>(KOTA_VERDICT_ACTIVE),
                        static_cast<unsigned int>(KOTA_VERDICT_VIOLATION)));
    }
    return {};
}

} // namespace

MapUpdater::MapUpdater(int status_map_fd, int ip_to_inode_map_fd,
                       int netns_status_map_fd)
    : status_map_fd_(status_map_fd)
    , ip_to_inode_map_fd_(ip_to_inode_map_fd)
    , netns_status_map_fd_(netns_status_map_fd)
{
}

std::expected<kota_status_map_value, std::string>
MapUpdater::build_status_value(uint64_t inode, uint32_t profile_id,
                               uint32_t cilium_id, uint32_t verdict)
{
    struct kota_status_map_value value {};
    const int lookup_rc = bpf_map_lookup_elem(status_map_fd_, &inode, &value);
    if (lookup_rc != 0 && errno != ENOENT) {
        return std::unexpected(
            std::format("StatusMap lookup failed for inode {}: {}", inode,
                        std::strerror(errno)));
    }
    if (lookup_rc != 0)
        std::memset(&value, 0, sizeof(value));

    auto now_mono = monotonic_now_ns();
    if (!now_mono)
        return std::unexpected(now_mono.error());

    value.schema_version       = KOTA_SCHEMA_VERSION;
    value.verdict              = verdict;
    value.profile_id           = profile_id;
    value.cilium_id            = cilium_id;
    value.updated_monotonic_ns = *now_mono;

    if (value.birth_ns == 0) {
        auto now_boot = boottime_now_ns();
        if (!now_boot)
            return std::unexpected(now_boot.error());
        value.birth_ns = *now_boot;
    }

    return value;
}

std::expected<void, std::string>
MapUpdater::upsert_status(const StatusUpsert &req)
{
    if (status_map_fd_ < 0)
        return std::unexpected("StatusMap fd is invalid");
    if (auto v = validate_verdict(req.verdict); !v)
        return std::unexpected(v.error());

    /*
     * Lock ordering for parallel resolver + telemetry updates:
     * - Only MapUpdater::write_mu_ is taken in map write paths.
     * - Callers must not hold resolver catalog locks while calling this API.
     * This keeps S4.2 fault transitions and resolver upserts free of lock cycles.
     */
    std::lock_guard<std::mutex> lock(write_mu_);

    if (req.inode == 0) {
        if (req.trigger_inode.has_value()) {
            return std::unexpected(
                "StatusMap global verdict transition cannot use trigger_inode");
        }

        __u64 prev_key = 0;
        __u64 key      = 0;
        bool  have_prev = false;
        while (true) {
            errno = 0;
            const int next_rc = bpf_map_get_next_key(
                status_map_fd_, have_prev ? &prev_key : nullptr, &key);
            if (next_rc != 0) {
                if (errno == ENOENT)
                    break;
                return std::unexpected(std::format(
                    "StatusMap global transition key scan failed: {}",
                    std::strerror(errno)));
            }

            struct kota_status_map_value value {};
            if (bpf_map_lookup_elem(status_map_fd_, &key, &value) != 0) {
                return std::unexpected(
                    std::format("StatusMap lookup failed for inode {}: {}", key,
                                std::strerror(errno)));
            }

            /*
             * Policy gate: only managed pods (profile_id != 0) are eligible for
             * global telemetry verdict transitions. Unmanaged entries remain ACTIVE.
             */
            if (value.profile_id == 0) {
                prev_key  = key;
                have_prev = true;
                continue;
            }

            auto now_mono = monotonic_now_ns();
            if (!now_mono)
                return std::unexpected(now_mono.error());

            value.schema_version       = KOTA_SCHEMA_VERSION;
            value.verdict              = req.verdict;
            value.updated_monotonic_ns = *now_mono;

            if (bpf_map_update_elem(status_map_fd_, &key, &value, BPF_ANY) != 0) {
                return std::unexpected(std::format(
                    "StatusMap global transition update failed for inode {}: {}",
                    key, std::strerror(errno)));
            }

            prev_key  = key;
            have_prev = true;
        }

        if (netns_status_map_fd_ >= 0) {
            __u64 prev_key = 0;
            __u64 key      = 0;
            bool  have_prev = false;
            while (true) {
                errno = 0;
                const int next_rc = bpf_map_get_next_key(
                    netns_status_map_fd_, have_prev ? &prev_key : nullptr, &key);
                if (next_rc != 0) {
                    if (errno == ENOENT)
                        break;
                    return std::unexpected(std::format(
                        "NetnsStatus global transition key scan failed: {}",
                        std::strerror(errno)));
                }

                struct kota_status_map_value value {};
                if (bpf_map_lookup_elem(netns_status_map_fd_, &key, &value) != 0) {
                    return std::unexpected(
                        std::format("NetnsStatus lookup failed for cookie {}: {}", key,
                                    std::strerror(errno)));
                }
                if (value.profile_id != 0) {
                    auto now_mono = monotonic_now_ns();
                    if (!now_mono)
                        return std::unexpected(now_mono.error());
                    value.schema_version       = KOTA_SCHEMA_VERSION;
                    value.verdict              = req.verdict;
                    value.updated_monotonic_ns = *now_mono;
                    if (bpf_map_update_elem(netns_status_map_fd_, &key, &value,
                                            BPF_ANY) != 0) {
                        return std::unexpected(std::format(
                            "NetnsStatus global transition update failed for cookie {}: {}",
                            key, std::strerror(errno)));
                    }
                }

                prev_key  = key;
                have_prev = true;
            }
        }

        return {};
    }

    auto primary =
        build_status_value(req.inode, req.profile_id, req.cilium_id, req.verdict);
    if (!primary)
        return std::unexpected(primary.error());

    if (bpf_map_update_elem(status_map_fd_, &req.inode, &(*primary), BPF_ANY) !=
        0) {
        return std::unexpected(
            std::format("StatusMap update failed for inode {}: {}", req.inode,
                        std::strerror(errno)));
    }

    if (req.trigger_inode && *req.trigger_inode != req.inode) {
        auto trigger = build_status_value(*req.trigger_inode, req.profile_id,
                                          req.cilium_id, req.verdict);
        if (!trigger)
            return std::unexpected(trigger.error());
        if ((*trigger).birth_ns == 0)
            (*trigger).birth_ns = (*primary).birth_ns;

        if (bpf_map_update_elem(status_map_fd_, &(*req.trigger_inode), &(*trigger),
                                BPF_ANY) != 0) {
            return std::unexpected(std::format(
                "StatusMap trigger update failed for inode {}: {}",
                *req.trigger_inode, std::strerror(errno)));
        }
    }

    return {};
}

std::expected<void, std::string>
MapUpdater::upsert_ip_to_inode(const std::string &pod_ip, uint64_t inode)
{
    if (ip_to_inode_map_fd_ < 0)
        return {};
    if (inode == 0)
        return std::unexpected("IP_to_Inode upsert requires non-zero inode");

    struct in_addr addr {};
    if (::inet_pton(AF_INET, pod_ip.c_str(), &addr) != 1)
        return std::unexpected("pod_ip is not IPv4: " + pod_ip);

    const __u32 ip_key = addr.s_addr;
    const __u64 ino    = inode;

    std::lock_guard<std::mutex> lock(write_mu_);
    if (bpf_map_update_elem(ip_to_inode_map_fd_, &ip_key, &ino, BPF_ANY) != 0) {
        return std::unexpected("kota_ip_to_inode update failed: " +
                               std::string(std::strerror(errno)));
    }
    return {};
}

std::expected<void, std::string>
MapUpdater::delete_ip_to_inode(const std::string &pod_ip)
{
    if (ip_to_inode_map_fd_ < 0)
        return {};

    struct in_addr addr {};
    if (::inet_pton(AF_INET, pod_ip.c_str(), &addr) != 1)
        return std::unexpected("pod_ip is not IPv4: " + pod_ip);

    const __u32 ip_key = addr.s_addr;

    std::lock_guard<std::mutex> lock(write_mu_);
    if (bpf_map_delete_elem(ip_to_inode_map_fd_, &ip_key) != 0 &&
        errno != ENOENT) {
        return std::unexpected("kota_ip_to_inode delete failed: " +
                               std::string(std::strerror(errno)));
    }
    return {};
}

} // namespace kota
