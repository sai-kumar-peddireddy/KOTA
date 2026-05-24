#pragma once

#include "../policy/kota_profile.h"

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>

namespace kota {

struct GpuHealthSample {
    bool   have_temperature = false;
    double temperature_c    = 0.0;
    bool   have_memory_error = false;
    bool   memory_error     = false;
};

using GpuHealthSink = std::function<void(const GpuHealthSample &, kota_decide)>;

struct NvmlPollerConfig {
    std::chrono::milliseconds poll_interval{1000};
    std::uint32_t             violation_debounce_samples = 3;
    std::uint32_t             clear_debounce_samples = 3;
};

class NvmlPoller {
  public:
    NvmlPoller(NvmlPollerConfig config, GpuHealthSink sink) noexcept;
    ~NvmlPoller();

    NvmlPoller(const NvmlPoller &) = delete;
    NvmlPoller &operator=(const NvmlPoller &) = delete;

    std::expected<void, std::string> init() noexcept;
    void shutdown() noexcept;

    std::expected<std::optional<kota_decide>, std::string>
    poll_once(const KotaProfile &profile) noexcept;

  private:
    struct Impl;

    NvmlPollerConfig config_{};
    GpuHealthSink    sink_{};
    Impl            *impl_ = nullptr;
    std::uint32_t    unhealthy_streak_ = 0;
    std::uint32_t    healthy_streak_   = 0;
    kota_decide      stable_state_     = kota_decide::active;
    bool             initialised_      = false;
};

} // namespace kota
