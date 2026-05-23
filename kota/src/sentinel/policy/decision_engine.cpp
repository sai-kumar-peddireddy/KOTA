#include "kota_profile.h"

namespace kota {

kota_decide decide_from_gpu_telemetry(const KotaProfile       &profile,
                                     const GpuTelemetrySample &s) noexcept
{
    /*
     * any breached hardware signal maps directly to VIOLATION so both network
     * and hardware gates can consume the same StatusMap verdict.
     */
    const bool temperature_breach =
        profile.nvml.max_temperature_c && s.have_temperature &&
        s.temperature_c > *profile.nvml.max_temperature_c;
    if (temperature_breach) {
        return kota_decide::violation;
    }

    const bool memory_error_breach = profile.nvml.memory_error_causes_violation &&
                                     *profile.nvml.memory_error_causes_violation &&
                                     s.have_memory_error && s.memory_error;
    if (memory_error_breach) {
        return kota_decide::violation;
    }
    return kota_decide::active;
}

} // namespace kota
