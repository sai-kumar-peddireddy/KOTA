#pragma once

#include <expected>
#include <mutex>
#include <stop_token>
#include <string>
#include <unordered_map>

#include "kotad_ring_dispatch.h"
#include "../telemetry/nvml_poller.h"

namespace kota {

class BpfLoader;
class OtelExporter;
struct KotaProfile;

/** Phase-2 NVML debounce loop + global StatusMap reconcile (docs/flow.md). */
void run_kotad_nvml_monitor_loop(
    std::stop_token                         st,
    BpfLoader                              &loader,
    OtelExporter                           &otel,
    std::mutex                             &enforced_mu,
    const std::unordered_map<std::uint64_t, KotaEnforcedHostRecord>
        &enforced_hosts,
    NvmlPollerConfig                        poll_cfg,
    GpuHealthSink                           sample_sink,
    std::expected<KotaProfile, std::string> profile_or_err);

} // namespace kota
