#include "nvml_poller.h"

#include "../policy/kota_profile.h"

#include <dlfcn.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace kota {

namespace {

using nvmlReturn_t = int;
using nvmlDevice_t = void *;

constexpr nvmlReturn_t NVML_SUCCESS = 0;

using nvmlInit_v2_t = nvmlReturn_t (*)();
using nvmlShutdown_t = nvmlReturn_t (*)();
using nvmlDeviceGetCount_v2_t = nvmlReturn_t (*)(unsigned int *);
using nvmlDeviceGetHandleByIndex_v2_t =
    nvmlReturn_t (*)(unsigned int, nvmlDevice_t *);
using nvmlDeviceGetTemperature_t =
    nvmlReturn_t (*)(nvmlDevice_t, unsigned int, unsigned int *);
using nvmlDeviceGetTotalEccErrors_t =
    nvmlReturn_t (*)(nvmlDevice_t, unsigned int, unsigned int, unsigned long long *);
using nvmlErrorString_t = const char *(*)(nvmlReturn_t);

constexpr unsigned int NVML_TEMPERATURE_GPU = 0;
constexpr unsigned int NVML_MEMORY_ERROR_TYPE_UNCORRECTED = 1;
constexpr unsigned int NVML_VOLATILE_ECC = 0;

std::string nvml_error_to_string(nvmlErrorString_t fn, nvmlReturn_t rc)
{
    if (!fn) {
        return "NVML error code " + std::to_string(rc);
    }
    const char *s = fn(rc);
    if (!s || !*s) {
        return "NVML error code " + std::to_string(rc);
    }
    return std::string{s};
}

std::optional<std::string>
describe_unhealthy_reason(const KotaProfile &profile,
                          const GpuHealthSample &sample)
{
    if (profile.nvml.max_temperature_c && sample.have_temperature &&
        sample.temperature_c > *profile.nvml.max_temperature_c) {
        return "temperature " + std::to_string(sample.temperature_c) +
               "C > threshold " + std::to_string(*profile.nvml.max_temperature_c) +
               "C";
    }
    if (profile.nvml.memory_error_causes_violation &&
        *profile.nvml.memory_error_causes_violation && sample.have_memory_error &&
        sample.memory_error) {
        return "uncorrected volatile ECC error observed";
    }
    return std::nullopt;
}

} // namespace

struct NvmlPoller::Impl {
    void *so_handle = nullptr;

    nvmlInit_v2_t                init_v2 = nullptr;
    nvmlShutdown_t               shutdown = nullptr;
    nvmlDeviceGetCount_v2_t      device_get_count = nullptr;
    nvmlDeviceGetHandleByIndex_v2_t device_get_handle = nullptr;
    nvmlDeviceGetTemperature_t   device_get_temperature = nullptr;
    nvmlDeviceGetTotalEccErrors_t device_get_total_ecc_errors = nullptr;
    nvmlErrorString_t            error_string = nullptr;

    bool init_done = false;

    ~Impl()
    {
        if (init_done && shutdown) {
            static_cast<void>(shutdown());
        }
        if (so_handle) {
            dlclose(so_handle);
            so_handle = nullptr;
        }
    }
};

NvmlPoller::NvmlPoller(NvmlPollerConfig config, GpuHealthSink sink) noexcept
    : config_(std::move(config)), sink_(std::move(sink)), impl_(new Impl{})
{
    if (config_.violation_debounce_samples == 0)
        config_.violation_debounce_samples = 1;
    if (config_.clear_debounce_samples == 0)
        config_.clear_debounce_samples = 1;
}

NvmlPoller::~NvmlPoller()
{
    shutdown();
    delete impl_;
    impl_ = nullptr;
}

std::expected<void, std::string> NvmlPoller::init() noexcept
{
    if (!impl_) {
        return std::unexpected("nvml poller: internal state missing");
    }
    if (initialised_)
        return {};

    impl_->so_handle = dlopen("libnvidia-ml.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!impl_->so_handle) {
        return std::unexpected("nvml poller: dlopen libnvidia-ml.so.1 failed: " +
                               std::string(dlerror() ? dlerror() : "unknown"));
    }

    auto resolve = [&](auto &fn, const char *name) -> bool {
        fn = reinterpret_cast<std::remove_reference_t<decltype(fn)>>(
            dlsym(impl_->so_handle, name));
        return fn != nullptr;
    };

    if (!resolve(impl_->init_v2, "nvmlInit_v2") ||
        !resolve(impl_->shutdown, "nvmlShutdown") ||
        !resolve(impl_->device_get_count, "nvmlDeviceGetCount_v2") ||
        !resolve(impl_->device_get_handle, "nvmlDeviceGetHandleByIndex_v2") ||
        !resolve(impl_->device_get_temperature, "nvmlDeviceGetTemperature") ||
        !resolve(impl_->device_get_total_ecc_errors, "nvmlDeviceGetTotalEccErrors") ||
        !resolve(impl_->error_string, "nvmlErrorString")) {
        const char *err = dlerror();
        return std::unexpected("nvml poller: required symbol lookup failed: " +
                               std::string(err ? err : "unknown"));
    }

    const nvmlReturn_t rc = impl_->init_v2();
    if (rc != NVML_SUCCESS) {
        return std::unexpected("nvml poller: nvmlInit_v2 failed: " +
                               nvml_error_to_string(impl_->error_string, rc));
    }
    impl_->init_done = true;
    initialised_ = true;
    return {};
}

void NvmlPoller::shutdown() noexcept
{
    if (!impl_)
        return;

    initialised_ = false;
    unhealthy_streak_ = 0;
    healthy_streak_ = 0;
}

std::expected<std::optional<kota_decide>, std::string>
NvmlPoller::poll_once(const KotaProfile &profile) noexcept
{
    if (!impl_ || !initialised_) {
        return std::unexpected("nvml poller: init() required before polling");
    }

    unsigned int count = 0;
    nvmlReturn_t rc = impl_->device_get_count(&count);
    if (rc != NVML_SUCCESS) {
        return std::unexpected("nvml poller: nvmlDeviceGetCount_v2 failed: " +
                               nvml_error_to_string(impl_->error_string, rc));
    }
    if (count == 0) {
        return std::unexpected("nvml poller: no GPU devices found");
    }

    GpuHealthSample sample{};
    bool any_memory_error = false;
    double max_temp = 0.0;
    bool have_any_temp = false;
    for (unsigned int i = 0; i < count; ++i) {
        nvmlDevice_t device = nullptr;
        rc = impl_->device_get_handle(i, &device);
        if (rc != NVML_SUCCESS || !device) {
            continue;
        }

        unsigned int temp = 0;
        rc = impl_->device_get_temperature(device, NVML_TEMPERATURE_GPU, &temp);
        if (rc == NVML_SUCCESS) {
            have_any_temp = true;
            max_temp = std::max(max_temp, static_cast<double>(temp));
        }

        unsigned long long ecc_errors = 0;
        rc = impl_->device_get_total_ecc_errors(
            device,
            NVML_MEMORY_ERROR_TYPE_UNCORRECTED,
            NVML_VOLATILE_ECC,
            &ecc_errors);
        if (rc == NVML_SUCCESS && ecc_errors > 0) {
            any_memory_error = true;
        }
    }

    sample.have_temperature = have_any_temp;
    sample.temperature_c = max_temp;
    sample.have_memory_error = true;
    sample.memory_error = any_memory_error;

    const GpuTelemetrySample policy_sample{
        .have_temperature = sample.have_temperature,
        .temperature_c = sample.temperature_c,
        .have_memory_error = sample.have_memory_error,
        .memory_error = sample.memory_error,
    };

    const auto immediate = decide_from_gpu_telemetry(profile, policy_sample);
    const bool unhealthy = immediate == kota_decide::violation;
    const auto unhealthy_reason = unhealthy
                                      ? describe_unhealthy_reason(profile, sample)
                                      : std::nullopt;

    const std::uint32_t prev_healthy_streak = healthy_streak_;
    const auto          previous_stable      = stable_state_;

    if (unhealthy) {
        ++unhealthy_streak_;
        healthy_streak_ = 0;
    } else {
        ++healthy_streak_;
        unhealthy_streak_ = 0;
    }

    const auto next_state = unhealthy ? kota_decide::violation : kota_decide::active;
    const std::uint32_t required = unhealthy ? config_.violation_debounce_samples
                                             : config_.clear_debounce_samples;

    if (previous_stable == kota_decide::violation && unhealthy &&
        prev_healthy_streak > 0) {
        std::cout
            << "[KOTA] NVML recovery cancelled: unhealthy sample observed before "
            << "clear hysteresis window completed\n";
    }

    if (previous_stable == kota_decide::violation && !unhealthy &&
        next_state != stable_state_) {
        std::cout << "[KOTA] NVML recovery pending: healthy_streak="
                  << healthy_streak_ << "/" << required << '\n';
    }

    if (next_state == stable_state_) {
        if (stable_state_ == kota_decide::violation && unhealthy_reason) {
            std::cout << "[KOTA] NVML violation retained: " << *unhealthy_reason
                      << '\n';
        }
        if (sink_)
            sink_(sample, stable_state_);
        return std::optional<kota_decide>{};
    }

    const std::uint32_t streak = unhealthy ? unhealthy_streak_ : healthy_streak_;
    if (streak < required) {
        if (unhealthy && unhealthy_reason) {
            std::cout << "[KOTA] NVML violation pending: unhealthy_streak="
                      << unhealthy_streak_ << "/" << required
                      << " reason=" << *unhealthy_reason << '\n';
        }
        if (sink_)
            sink_(sample, stable_state_);
        return std::optional<kota_decide>{};
    }

    stable_state_ = next_state;
    if (previous_stable == kota_decide::active &&
        stable_state_ == kota_decide::violation) {
        std::cout << "[KOTA] NVML violation latched: unhealthy streak reached "
                  << required << " sample(s) (violation_debounce)";
        if (unhealthy_reason)
            std::cout << " reason=" << *unhealthy_reason;
        std::cout << '\n';
    }
    if (previous_stable == kota_decide::violation &&
        stable_state_ == kota_decide::active) {
        std::cout << "[KOTA] NVML recovery completed: clear hysteresis satisfied ("
                  << required << " healthy sample(s))\n";
    }
    if (sink_)
        sink_(sample, stable_state_);
    return std::optional<kota_decide>{stable_state_};
}

} // namespace kota
