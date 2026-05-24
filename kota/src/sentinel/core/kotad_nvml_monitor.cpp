#include "kotad_nvml_monitor.h"

#include <iostream>
#include <cstdint>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

#include "../maps/bpf_loader.h"
#include "../maps/map_updater.h"
#include "../policy/kota_profile.h"
#include "../telemetry/otel_exporter.h"
#include "../../../include/shared/kota_common.h"

namespace kota {

void run_kotad_nvml_monitor_loop(
    std::stop_token                         st,
    BpfLoader                              &loader,
    OtelExporter                           &otel,
    std::mutex                             &enforced_mu,
    const std::unordered_map<std::uint64_t, KotaEnforcedHostRecord>
        &enforced_hosts,
    NvmlPollerConfig                        poll_cfg,
    GpuHealthSink                           sample_sink,
    std::expected<KotaProfile, std::string> profile_or_err)
{
    if (!profile_or_err) {
        std::cout << "[KOTA] Phase 2 monitoring disabled: " << profile_or_err.error()
                  << '\n';
        while (!st.stop_requested())
            std::this_thread::sleep_for(std::chrono::seconds(30));
        return;
    }

    const KotaProfile &profile = *profile_or_err;
    NvmlPoller         poller{poll_cfg, std::move(sample_sink)};

    if (auto r = poller.init(); !r) {
        std::cout << "[KOTA] Phase 2 monitoring: NVML unavailable: " << r.error()
                  << '\n';
        while (!st.stop_requested())
            std::this_thread::sleep_for(std::chrono::seconds(30));
        return;
    }

    std::cout << "[KOTA] Phase 2 monitoring active (poll=" << poll_cfg.poll_interval.count()
              << "ms"
              << ", deb_violation=" << poll_cfg.violation_debounce_samples
              << ", deb_clear=" << poll_cfg.clear_debounce_samples << ")\n";
    otel.record_nvml_sample(0.0, 0, static_cast<double>(poll_cfg.poll_interval.count()),
                            false);

    auto current_telemetry_state = kota_decide::active;
    std::optional<std::chrono::steady_clock::time_point> violation_started_at{};
    while (!st.stop_requested()) {
        auto step = poller.poll_once(profile);
        if (!step) {
            std::cout << "[KOTA] NVML poll error: " << step.error() << '\n';
        } else if (step->has_value()) {
            std::cout << "[KOTA] NVML debounced transition -> "
                      << (step->value() == kota_decide::active ? "ACTIVE" : "VIOLATION")
                      << '\n';
            current_telemetry_state = step->value();
            const auto propagation_t0 = std::chrono::steady_clock::now();
            MapUpdater updater{loader.map_fd(KOTA_MAP_STATUS_MAP),
                               loader.map_fd(KOTA_MAP_IP_TO_INODE),
                               loader.map_fd(KOTA_MAP_NETNS_STATUS)};
            MapUpdater::StatusUpsert req{};
            req.inode   = 0;
            req.verdict = verdict_from_decision(step->value());
            if (auto r = updater.upsert_status(req); !r) {
                std::cerr << "[KOTA] telemetry verdict transition failed: " << r.error()
                          << '\n';
            } else {
                std::cout << "[KOTA] telemetry verdict transition applied to StatusMap\n";
                const auto propagation_t1 = std::chrono::steady_clock::now();
                const auto propagation_ms =
                    std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(
                        propagation_t1 - propagation_t0)
                        .count();
                std::vector<std::pair<std::string, std::string>> labels;
                {
                    std::lock_guard<std::mutex> lock(enforced_mu);
                    labels.reserve(enforced_hosts.size());
                    for (const auto &[inode, record] : enforced_hosts) {
                        static_cast<void>(inode);
                        if (record.pod_name.empty() || record.namespace_name.empty())
                            continue;
                        labels.emplace_back(record.pod_name, record.namespace_name);
                    }
                }
                if (labels.empty()) {
                    otel.record_enforcement_propagation_latency_ms(propagation_ms);
                    otel.record_verdict_transition("", "", "UNKNOWN",
                                                   step->value() == kota_decide::active
                                                       ? "ACTIVE"
                                                       : "VIOLATION");
                    otel.record_verdict_state(
                        "", "",
                        step->value() == kota_decide::active ? int64_t{0} : int64_t{1});
                } else {
                    for (const auto &[pod, ns] : labels) {
                        otel.record_enforcement_propagation_latency_ms(
                            propagation_ms, pod, ns);
                        otel.record_verdict_transition(
                            pod, ns,
                            step->value() == kota_decide::active ? "VIOLATION" : "ACTIVE",
                            step->value() == kota_decide::active ? "ACTIVE" : "VIOLATION");
                        otel.record_verdict_state(
                            pod, ns,
                            step->value() == kota_decide::active ? int64_t{0} : int64_t{1});
                    }
                }
                if (step->value() == kota_decide::violation) {
                    violation_started_at = propagation_t1;
                } else if (step->value() == kota_decide::active &&
                           violation_started_at.has_value()) {
                    const auto duration_seconds =
                        std::chrono::duration_cast<std::chrono::duration<double>>(
                            propagation_t1 - *violation_started_at)
                            .count();
                    if (labels.empty()) {
                        otel.record_violation_duration_seconds(duration_seconds);
                    } else {
                        for (const auto &[pod, ns] : labels) {
                            otel.record_violation_duration_seconds(
                                duration_seconds, pod, ns);
                            otel.record_recovery_event(pod, ns);
                        }
                    }
                    violation_started_at.reset();
                }
                otel.record_bpf_map_update("kota_status_map", "upsert_status");
            }
        }

        {
            MapUpdater updater{loader.map_fd(KOTA_MAP_STATUS_MAP),
                               loader.map_fd(KOTA_MAP_IP_TO_INODE),
                               loader.map_fd(KOTA_MAP_NETNS_STATUS)};
            MapUpdater::StatusUpsert req{};
            req.inode   = 0;
            req.verdict = verdict_from_decision(current_telemetry_state);
            if (auto r = updater.upsert_status(req); !r) {
                std::cerr << "[KOTA] telemetry verdict reconcile failed: " << r.error()
                          << '\n';
            } else {
                otel.record_bpf_map_update("kota_status_map", "reconcile_status");
            }
        }
        std::int64_t enforced_count = 0;
        {
            std::lock_guard<std::mutex> lock(enforced_mu);
            enforced_count = static_cast<std::int64_t>(enforced_hosts.size());
        }
        otel.record_workload_counts(enforced_count, enforced_count);
        std::this_thread::sleep_for(poll_cfg.poll_interval);
    }
}

} // namespace kota
