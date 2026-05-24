#pragma once

#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>

namespace kota {

/*
 * OpenTelemetry metrics bridge used by kotad runtime.
 * Installs a global MeterProvider with service Resource metadata.
 */
class OtelExporter {
public:
    OtelExporter() = default;

    std::expected<void, std::string> init(std::string_view endpoint);

    void record_violation(uint64_t cgroup_inode, uint32_t event_type);

    void record_gpu_stats(uint64_t cgroup_inode, uint64_t ioctl_count,
                          uint64_t vram_mb);

    void record_policy_latency(uint32_t policy_id, uint64_t latency_ns,
                               std::string_view pod = {},
                               std::string_view namespace_name = {});
    void record_enforcement_propagation_latency_ms(
        double latency_ms, std::string_view pod = {},
        std::string_view namespace_name = {});
    void record_violation_duration_seconds(double duration_seconds,
                                           std::string_view pod = {},
                                           std::string_view namespace_name = {});
    void record_packet_drop(std::string_view pod, std::string_view namespace_name,
                            uint16_t port, std::string_view direction,
                            uint64_t bytes = 1);
    void record_lsm_veto_event(std::string_view pod, std::string_view namespace_name,
                               std::string_view device,
                               std::string_view syscall);
    void record_verdict_transition(std::string_view pod, std::string_view namespace_name,
                                   std::string_view from_verdict,
                                   std::string_view to_verdict);
    void record_recovery_event(std::string_view pod, std::string_view namespace_name);
    void record_bpf_map_update(std::string_view map_name, std::string_view operation);
    void record_cgroup_event_processed(std::string_view event_type);
    void record_identity_resolution_failure(std::string_view reason);
    void record_policy_reload();
    void record_verdict_state(std::string_view pod, std::string_view namespace_name,
                              std::int64_t verdict_state);
    void record_nvml_sample(double temperature_c, std::int64_t utilisation_percent,
                            double poll_interval_ms, bool memory_error);
    void record_workload_counts(std::int64_t monitored_pods,
                                std::int64_t enforced_pods);
    void record_active_policies(std::int64_t active_policies);
    void record_uptime_seconds(double uptime_seconds);

    void shutdown();

private:
    bool initialised_ = false;
    struct Impl;
    std::shared_ptr<Impl> impl_;
};

} // namespace kota
