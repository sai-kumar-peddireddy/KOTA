#pragma once

#include "../../../include/shared/kota_common.h"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace kota {

struct KotaNvmlPolicy {
    std::optional<double> max_temperature_c; /* violation if sample temp > this */
    std::optional<bool>   memory_error_causes_violation;
};

/**
 * OCI-bound workload profile: management vs AI/data ports (docs/HLD.md) plus
 * optional hardware policy. Loaded from on-disk YAML (ProfileStore path).
 */
struct KotaProfile {
    std::uint32_t           schema_version = 0; /* must match file; CE == 1 */
    std::string             name;               /* non-empty */
    std::vector<std::uint16_t> management_ports;
    std::vector<std::uint16_t> ai_data_ports;   /* "AI" / data path */
    std::vector<std::uint32_t> blocked_ioctl_cmds; /* hex/decimal ioctl denylist */
    KotaNvmlPolicy          nvml;
};

/**
 * GPU-side samples for the policy engine (NVML poller will populate in S4).
 */
struct GpuTelemetrySample {
    bool   have_temperature = false;
    double temperature_c    = 0.0;
    bool   have_memory_error = false;
    bool   memory_error     = false;
};

std::expected<KotaProfile, std::string>
load_kota_profile_yaml(const std::filesystem::path &path);

std::expected<KotaProfile, std::string>
load_kota_profile_yaml_string(const std::string    &source,
                              const std::string    &label_for_errors);

/**
 * Desired map verdict: ACTIVE (gates open) vs VIOLATION (enforce restrictions).
 * No quarantine tier (docs/flow.md).
 */
enum class kota_decide {
    active,
    violation,
};

kota_decide decide_from_gpu_telemetry(const KotaProfile         &profile,
                                     const GpuTelemetrySample &sample) noexcept;

inline enum kota_verdict verdict_from_decision(kota_decide d) noexcept
{
    return d == kota_decide::active ? KOTA_VERDICT_ACTIVE
                                    : KOTA_VERDICT_VIOLATION;
}

} // namespace kota
