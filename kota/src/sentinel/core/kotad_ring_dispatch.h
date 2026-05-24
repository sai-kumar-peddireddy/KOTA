#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

#include "../maps/kota_bpf_user_abi.h"

namespace kota {

class PodResolver;
class ProfileStore;
class CiliumPeeker;
class ViolationLogger;
class OtelExporter;

/** Per-pod bookkeeping for cgroup teardown (IP attribution cleanup). */
struct KotaEnforcedHostRecord {
    std::string pod_ip;
    std::string pod_name;
    std::string namespace_name;
};

/**
 * Routes BPF ring-buffer events to logging, OTel, and PodResolver side effects.
 * Add new event types by extending dispatch() — avoid a single monolithic callback.
 */
class KotadRingDispatcher {
public:
    KotadRingDispatcher(PodResolver                    &resolver,
                        ProfileStore                   &profile_store,
                        CiliumPeeker                   &cilium,
                        ViolationLogger                &vlogger,
                        OtelExporter                   &otel,
                        int                             status_map_fd,
                        int                             cgroup_bridge_map_fd,
                        std::atomic<bool>              &stdout_network_drop_proof_logged,
                        std::atomic<int>                &birth_worker_count,
                        std::mutex                     &enforced_mu,
                        std::unordered_map<std::uint64_t, KotaEnforcedHostRecord>
                            &enforced_hosts);

    void dispatch(const kota_event &ev);

    /** Adapter for RingBufConsumer. */
    void operator()(const kota_event &ev) { dispatch(ev); }

private:
    /** stderr trace when `KOTA_DEBUG_RING_VIOLATIONS` is set. */
    void maybe_log_violation_class_ring_event(const kota_event &ev) const;
    /**
     * Each `KOTA_EVT_NETWORK_DROP` is already persisted via `ViolationLogger` in
     * `dispatch()`. This only prints a single stdout proof line (`BPF NETWORK_DROP
     * observed`) once per process so operators are not spammed — not a substitute
     * for per-drop logging.
     */
    void try_log_stdout_network_drop_proof_once(const kota_event &ev);
    void maybe_learn_ioctl_bridge_from_event(const kota_event &ev);
    void record_otel_metrics_for_ring_event(const kota_event &ev) const;
    void handle_pod_cgroup_death(const kota_event &ev);
    void start_async_pod_resolve_after_birth(std::uint64_t cgroup_inode);

    PodResolver                    &resolver_;
    ProfileStore                   &profile_store_;
    CiliumPeeker                   &cilium_;
    ViolationLogger                &vlogger_;
    OtelExporter                   &otel_;
    int                             status_map_fd_;
    int                             cgroup_bridge_map_fd_;
    std::atomic<bool>              &stdout_network_drop_proof_logged_;
    std::atomic<int>                &birth_worker_count_;
    std::mutex                     &enforced_mu_;
    std::unordered_map<std::uint64_t, KotaEnforcedHostRecord> &enforced_hosts_;
};

} // namespace kota
