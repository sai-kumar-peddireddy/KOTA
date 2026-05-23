#include "otel_exporter.h"

#include <chrono>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <atomic>
#if defined(KOTA_OTEL) && KOTA_OTEL && !defined(_WIN32)
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#if defined(KOTA_OTEL) && KOTA_OTEL
#include <opentelemetry/common/key_value_iterable_view.h>
#include <opentelemetry/context/context.h>
#include <opentelemetry/metrics/meter.h>
#include <opentelemetry/metrics/noop.h>
#include <opentelemetry/metrics/provider.h>
#include <opentelemetry/metrics/sync_instruments.h>
#include <opentelemetry/exporters/otlp/otlp_http_metric_exporter_factory.h>
#include <opentelemetry/exporters/otlp/otlp_http_metric_exporter_options.h>
#include <opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader_factory.h>
#include <opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader_options.h>
#include <opentelemetry/sdk/metrics/meter_context_factory.h>
#include <opentelemetry/sdk/metrics/meter_provider.h>
#include <opentelemetry/sdk/metrics/meter_provider_factory.h>
#include <opentelemetry/sdk/resource/resource.h>
#endif
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

namespace kota {

namespace {

bool otel_debug_enabled()
{
    const char *e = std::getenv("KOTA_OTEL_DEBUG");
    return e && (e[0] == '1' || e[0] == 't' || e[0] == 'T');
}

/** Append OTLP `/v1/metrics` path when callers pass scheme+host (:port). */
std::string otlp_http_metrics_url_from_endpoint(std::string_view base_endpoint)
{
    std::string s(base_endpoint);
    while (!s.empty() && (s.back() == '/'))
        s.pop_back();
    if (s.empty())
        return {};
    if (s.find("/v1/metrics") != std::string::npos ||
        s.find("/v1/logs") != std::string::npos || s.find("/v1/traces") != std::string::npos)
        return s;
    return s + "/v1/metrics";
}

/** Milliseconds for PeriodicExportingMetricReader; default 3000 ms. */
std::chrono::milliseconds otel_metric_export_interval()
{
    const char *e = std::getenv("KOTA_OTEL_EXPORT_INTERVAL_MS");
    if (!e || !e[0])
        return std::chrono::milliseconds(3000);
    char             *end = nullptr;
    errno                 = 0;
    const long v = std::strtol(e, &end, 10);
    if (errno != 0 || end == e || (end && *end != '\0') || v <= 0)
        return std::chrono::milliseconds(3000);
    return std::chrono::milliseconds(v);
}

/** Best-effort: warn once if OTLP HTTP metrics URL looks reachable but refused (fail-soft UX). */
#if defined(KOTA_OTEL) && KOTA_OTEL && !defined(_WIN32)

static std::atomic<bool> otl_unreachable_warned;

static bool parse_http_host_port_prefix(const std::string &url, std::string *host,
                                        int *port)
{
    constexpr std::string_view http = "http://";
    if (url.size() <= http.size() ||
        url.compare(0, http.size(), http) != 0)
        return false;
    std::size_t start = http.size();
    const std::size_t slash =
        url.find('/', start);
    const std::string host_port =
        (slash == std::string::npos) ? url.substr(start)
                                    : url.substr(start, slash - start);
    const std::size_t colon = host_port.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon >= host_port.size() - 1)
        return false;
    *host = host_port.substr(0, colon);
    errno                           = 0;
    char *end                     = nullptr;
    const long pv = std::strtol(host_port.c_str() + colon + 1, &end, 10);
    if (errno != 0 || end == host_port.c_str() + colon + 1 ||
        (!end || *end != '\0') || pv <= 0 || pv > 65535)
        return false;
    *port = static_cast<int>(pv);
    return true;
}

/**
 * TCP probe: return true when we cannot prove the endpoint refused (starting late is OK).
 * Returns false only when SO_ERROR indicates ECONNREFUSED after a bounded connect attempt.
 */
static bool tcp_seems_unreachable_refused_only(const std::string &host, int port)
{
    struct addrinfo hints {};
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *result = nullptr;
    const std::string service = std::to_string(port);
    if (::getaddrinfo(host.c_str(), service.c_str(), &hints, &result) != 0 ||
        result == nullptr)
        return false;
    int fd =
        ::socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (fd < 0) {
        ::freeaddrinfo(result);
        return false;
    }
    const int fl = ::fcntl(fd, F_GETFL, 0);
    if (::fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0) {
        ::close(fd);
        ::freeaddrinfo(result);
        return false;
    }
    const int cr = ::connect(fd, result->ai_addr,
                             static_cast<socklen_t>(result->ai_addrlen));
    if (cr == 0) {
        ::close(fd);
        ::freeaddrinfo(result);
        return false;
    }
    if (cr < 0 && errno != EINPROGRESS) {
        ::close(fd);
        ::freeaddrinfo(result);
        return false;
    }
    ::freeaddrinfo(result);

    struct pollfd pfd {};
    pfd.fd     = fd;
    pfd.events = POLLOUT;
    const int pret = ::poll(&pfd, 1, 200);
    if (pret <= 0) {
        ::close(fd);
        return false;
    }
    int       so_err = 0;
    socklen_t sl     = sizeof(so_err);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &sl) != 0) {
        ::close(fd);
        return false;
    }
    ::close(fd);
    return so_err == ECONNREFUSED;
}

static void schedule_otlp_unreachable_warning(std::string metrics_url)
{
    std::thread(
        [](std::string url) {
            std::this_thread::sleep_for(std::chrono::milliseconds(450));
            std::string host;
            int         port = 0;
            if (!parse_http_host_port_prefix(url, &host, &port))
                return;
            if (!tcp_seems_unreachable_refused_only(host, port))
                return;
            bool expected = false;
            if (!otl_unreachable_warned.compare_exchange_strong(expected, true))
                return;
            std::cerr
                << "[KOTA] OTLP metrics endpoint unreachable (fail-soft; exports retry).\n";
        },
        std::move(metrics_url))
        .detach();
}

#else

static void schedule_otlp_unreachable_warning(const std::string &/*metrics_url*/) {}

#endif // KOTA_OTEL && !WIN32

} // namespace

struct OtelExporter::Impl {
#if defined(KOTA_OTEL) && KOTA_OTEL
    opentelemetry::nostd::shared_ptr<opentelemetry::metrics::Meter> meter;
    std::shared_ptr<opentelemetry::sdk::metrics::MeterProvider> sdk_provider;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<uint64_t>>
        violation_events_counter;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<uint64_t>>
        gpu_ioctl_counter;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<double>>
        gpu_vram_mb_histogram;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<double>>
        identity_resolution_latency_ms_histogram;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<double>>
        enforcement_propagation_latency_ms_histogram;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<double>>
        violation_duration_seconds_histogram;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<uint64_t>>
        packets_dropped_total_counter;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<uint64_t>>
        bytes_dropped_total_counter;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<uint64_t>>
        lsm_veto_events_total_counter;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<uint64_t>>
        verdict_transitions_total_counter;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<uint64_t>>
        recovery_events_total_counter;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<uint64_t>>
        bpf_map_updates_total_counter;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<uint64_t>>
        cgroup_events_processed_total_counter;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<uint64_t>>
        identity_resolution_failures_total_counter;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<uint64_t>>
        policy_reloads_total_counter;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Counter<uint64_t>>
        nvml_memory_errors_total_counter;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<double>>
        verdict_state_gauge;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<double>>
        nvml_gpu_temp_celsius_gauge;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<double>>
        nvml_gpu_utilisation_percent_gauge;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<double>>
        nvml_poll_interval_ms_gauge;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<double>>
        active_policies_total_gauge;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<double>>
        pods_monitored_total_gauge;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<double>>
        pods_enforced_total_gauge;
    opentelemetry::nostd::unique_ptr<opentelemetry::metrics::Histogram<double>>
        uptime_seconds_gauge;
#endif
};

std::expected<void, std::string> OtelExporter::init(std::string_view endpoint)
{
    if (initialised_)
        return {};

    impl_ = std::make_shared<Impl>();

#if defined(KOTA_OTEL) && KOTA_OTEL
    namespace metrics_api = opentelemetry::metrics;
    namespace sdk_metrics = opentelemetry::sdk::metrics;
    namespace sdk_resource = opentelemetry::sdk::resource;

    std::ostringstream instance_id;
    instance_id << "kotad-" << std::this_thread::get_id() << "-"
                << std::chrono::steady_clock::now().time_since_epoch().count();
    const std::string service_instance_id = instance_id.str();
    const std::string service_version = "0.1.0";
    const std::string endpoint_programmatic{endpoint};

    /*
     * Standard OTEL env overrides (`OTEL_EXPORTER_OTLP_ENDPOINT`, metrics-specific variants)
     * fill `OtlpHttpMetricExporterOptions` in its default constructor. Kotad optionally
     * supplies a non-env base URL when those env vars are unset (see kotad_runtime).
     */
    opentelemetry::exporter::otlp::OtlpHttpMetricExporterOptions otlp_metric_opts{};
    const bool env_sets_otlp =
        std::getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != nullptr ||
        std::getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT") != nullptr;
    if (!env_sets_otlp && !endpoint_programmatic.empty()) {
        const std::string u =
            otlp_http_metrics_url_from_endpoint(endpoint_programmatic);
        if (!u.empty())
            otlp_metric_opts.url = u;
    }

    schedule_otlp_unreachable_warning(otlp_metric_opts.url);

    opentelemetry::sdk::resource::ResourceAttributes attrs = {
        {"service.name", "kotad"},
        {"service.instance.id", service_instance_id},
        {"service.version", service_version},
        {"kota.otel.endpoint", otlp_metric_opts.url},
    };
    auto resource = sdk_resource::Resource::Create(attrs);

    auto metric_exporter =
        opentelemetry::exporter::otlp::OtlpHttpMetricExporterFactory::Create(
            otlp_metric_opts);
    if (!metric_exporter) {
        impl_.reset();
        return std::unexpected("failed to create OTLP HTTP metric exporter");
    }

    sdk_metrics::PeriodicExportingMetricReaderOptions reader_options{};
    reader_options.export_interval_millis = otel_metric_export_interval();
    reader_options.export_timeout_millis    = std::chrono::milliseconds(10000);

    auto reader =
        sdk_metrics::PeriodicExportingMetricReaderFactory::Create(
            std::move(metric_exporter), reader_options);

    auto views =
        std::make_unique<sdk_metrics::ViewRegistry>();
    auto context =
        sdk_metrics::MeterContextFactory::Create(std::move(views), resource);
    context->AddMetricReader(std::move(reader));

    auto u_provider = sdk_metrics::MeterProviderFactory::Create(std::move(context));
    std::shared_ptr<metrics_api::MeterProvider> api_provider(std::move(u_provider));
    metrics_api::Provider::SetMeterProvider(api_provider);
    impl_->sdk_provider =
        std::static_pointer_cast<sdk_metrics::MeterProvider>(api_provider);

    impl_->meter = metrics_api::Provider::GetMeterProvider()->GetMeter("kotad");
    if (impl_->meter == nullptr) {
        impl_.reset();
        return std::unexpected("failed to acquire global OTel meter");
    }

    initialised_ = true;

    impl_->violation_events_counter =
        impl_->meter->CreateUInt64Counter("kota_otel_violation_events_total",
                                          "Ring-event violation class counter", "1");
    impl_->gpu_ioctl_counter =
        impl_->meter->CreateUInt64Counter("kota_otel_gpu_ioctl_total",
                                          "GPU activity count from ring events", "1");
    impl_->gpu_vram_mb_histogram =
        impl_->meter->CreateDoubleHistogram("kota_otel_gpu_vram_mb",
                                            "GPU VRAM usage observations", "MB");
    impl_->identity_resolution_latency_ms_histogram =
        impl_->meter->CreateDoubleHistogram("kota_identity_resolution_latency_ms",
                                            "Identity resolution latency in milliseconds", "ms");
    impl_->enforcement_propagation_latency_ms_histogram =
        impl_->meter->CreateDoubleHistogram("kota_enforcement_propagation_latency_ms",
                                            "NVML fault to StatusMap update latency", "ms");
    impl_->violation_duration_seconds_histogram =
        impl_->meter->CreateDoubleHistogram("kota_violation_duration_seconds",
                                            "Time spent in violation state before recovery", "s");
    impl_->packets_dropped_total_counter = impl_->meter->CreateUInt64Counter(
        "kota_packets_dropped_total", "Dropped packet count by policy enforcement", "1");
    impl_->bytes_dropped_total_counter = impl_->meter->CreateUInt64Counter(
        "kota_bytes_dropped_total", "Dropped bytes by policy enforcement", "By");
    impl_->lsm_veto_events_total_counter = impl_->meter->CreateUInt64Counter(
        "kota_lsm_veto_events_total", "LSM veto count for blocked ioctls and mmaps", "1");
    impl_->verdict_transitions_total_counter = impl_->meter->CreateUInt64Counter(
        "kota_verdict_transitions_total", "Verdict transition count per workload", "1");
    impl_->recovery_events_total_counter = impl_->meter->CreateUInt64Counter(
        "kota_recovery_events_total", "Recovery transition count from violation to active", "1");
    impl_->bpf_map_updates_total_counter = impl_->meter->CreateUInt64Counter(
        "kota_bpf_map_updates_total", "BPF map update operations emitted by kotad", "1");
    impl_->cgroup_events_processed_total_counter = impl_->meter->CreateUInt64Counter(
        "kota_cgroup_events_processed_total", "Ring-buffer cgroup lifecycle events processed", "1");
    impl_->identity_resolution_failures_total_counter = impl_->meter->CreateUInt64Counter(
        "kota_identity_resolution_failures_total", "Pod identity resolution failures", "1");
    impl_->policy_reloads_total_counter = impl_->meter->CreateUInt64Counter(
        "kota_policy_reloads_total", "Policy load or reload operations", "1");
    impl_->nvml_memory_errors_total_counter = impl_->meter->CreateUInt64Counter(
        "kota_nvml_memory_errors_total", "NVML memory error observations", "1");
    impl_->verdict_state_gauge = impl_->meter->CreateDoubleHistogram(
        "kota_verdict_state", "Current workload verdict state (0=ACTIVE,1=VIOLATION,2=UNKNOWN)",
        "1");
    impl_->nvml_gpu_temp_celsius_gauge = impl_->meter->CreateDoubleHistogram(
        "kota_nvml_gpu_temp_celsius", "Latest observed GPU temperature", "C");
    impl_->nvml_gpu_utilisation_percent_gauge = impl_->meter->CreateDoubleHistogram(
        "kota_nvml_gpu_utilisation_percent", "Latest observed GPU utilisation percentage", "%");
    impl_->nvml_poll_interval_ms_gauge = impl_->meter->CreateDoubleHistogram(
        "kota_nvml_poll_interval_ms", "Configured NVML poll interval", "ms");
    impl_->active_policies_total_gauge = impl_->meter->CreateDoubleHistogram(
        "kota_active_policies_total", "Number of currently loaded policy profiles", "1");
    impl_->pods_monitored_total_gauge = impl_->meter->CreateDoubleHistogram(
        "kota_pods_monitored_total", "Number of pods currently tracked by kotad", "1");
    impl_->pods_enforced_total_gauge = impl_->meter->CreateDoubleHistogram(
        "kota_pods_enforced_total", "Number of pods currently under enforcement", "1");
    impl_->uptime_seconds_gauge = impl_->meter->CreateDoubleHistogram(
        "kotad_uptime_seconds", "kotad process uptime in seconds", "s");

    auto startup_counter = impl_->meter->CreateUInt64Counter(
        "kota_otel_startup_total", "OTel startup smoke counter", "1");
    startup_counter->Add(1);

    if (otel_debug_enabled()) {
        std::cout << "[KOTA] OtelExporter: global MeterProvider installed (endpoint="
                  << endpoint << ")\n";
    }
#else
    initialised_ = true;
    if (otel_debug_enabled()) {
        std::cout << "[KOTA] OtelExporter: metrics disabled (KOTA_OTEL=OFF)\n";
    }
#endif

    return {};
}

void OtelExporter::record_violation(uint64_t cgroup_inode, uint32_t event_type)
{
    if (!initialised_)
        return;
#if defined(KOTA_OTEL) && KOTA_OTEL
    if (impl_ && impl_->violation_events_counter) {
        impl_->violation_events_counter->Add(
            1, {{"event_type", static_cast<std::int64_t>(event_type)}});
    }
#endif
    if (otel_debug_enabled()) {
        std::cout << "[KOTA] OTel record_violation inode=" << cgroup_inode
                  << " event_type=" << event_type << '\n';
    }
    static_cast<void>(cgroup_inode);
}

void OtelExporter::record_gpu_stats(uint64_t cgroup_inode, uint64_t ioctl_count,
                                    uint64_t vram_mb)
{
    if (!initialised_)
        return;
#if defined(KOTA_OTEL) && KOTA_OTEL
    if (impl_ && impl_->gpu_ioctl_counter)
        impl_->gpu_ioctl_counter->Add(ioctl_count);
    if (impl_ && impl_->gpu_vram_mb_histogram) {
        impl_->gpu_vram_mb_histogram->Record(
            static_cast<double>(vram_mb), {{"cgroup_inode", static_cast<std::int64_t>(cgroup_inode)}},
            opentelemetry::context::Context{});
    }
#endif
    if (otel_debug_enabled()) {
        std::cout << "[KOTA] OTel record_gpu_stats inode=" << cgroup_inode
                  << " ioctl_count=" << ioctl_count << " vram_mb=" << vram_mb << '\n';
    }
    static_cast<void>(cgroup_inode);
}

void OtelExporter::record_policy_latency(uint32_t policy_id, uint64_t latency_ns,
                                         std::string_view pod,
                                         std::string_view namespace_name)
{
    if (!initialised_)
        return;
#if defined(KOTA_OTEL) && KOTA_OTEL
    const double latency_ms = static_cast<double>(latency_ns) / 1000000.0;
    if (impl_ && impl_->identity_resolution_latency_ms_histogram) {
        impl_->identity_resolution_latency_ms_histogram->Record(
            latency_ms,
            {{"policy_id", static_cast<std::int64_t>(policy_id)},
             {"pod", std::string(pod)},
             {"namespace", std::string(namespace_name)}},
            opentelemetry::context::Context{});
    }
#endif
    if (otel_debug_enabled()) {
        std::cout << "[KOTA] OTel record_policy_latency policy_id=" << policy_id
                  << " latency_ns=" << latency_ns << '\n';
    }
}

void OtelExporter::record_enforcement_propagation_latency_ms(
    double latency_ms, std::string_view pod, std::string_view namespace_name)
{
    if (!initialised_)
        return;
#if defined(KOTA_OTEL) && KOTA_OTEL
    if (impl_ && impl_->enforcement_propagation_latency_ms_histogram) {
        impl_->enforcement_propagation_latency_ms_histogram->Record(
            latency_ms,
            {{"pod", std::string(pod)},
             {"namespace", std::string(namespace_name)}},
            opentelemetry::context::Context{});
    }
#endif
}

void OtelExporter::record_violation_duration_seconds(
    double duration_seconds, std::string_view pod, std::string_view namespace_name)
{
    if (!initialised_)
        return;
#if defined(KOTA_OTEL) && KOTA_OTEL
    if (impl_ && impl_->violation_duration_seconds_histogram) {
        impl_->violation_duration_seconds_histogram->Record(
            duration_seconds,
            {{"pod", std::string(pod)},
             {"namespace", std::string(namespace_name)}},
            opentelemetry::context::Context{});
    }
#endif
}

void OtelExporter::shutdown()
{
    if (!initialised_)
        return;

#if defined(KOTA_OTEL) && KOTA_OTEL
    namespace metrics_api = opentelemetry::metrics;

    if (impl_ && impl_->sdk_provider) {
        static_cast<void>(impl_->sdk_provider->ForceFlush());
        static_cast<void>(impl_->sdk_provider->Shutdown());
    }
    std::shared_ptr<metrics_api::MeterProvider> noop_provider(
        new metrics_api::NoopMeterProvider);
    metrics_api::Provider::SetMeterProvider(noop_provider);
#endif

    impl_.reset();
    initialised_ = false;
    if (otel_debug_enabled())
        std::cout << "[KOTA] OtelExporter: shutdown complete\n";
}

void OtelExporter::record_packet_drop(std::string_view pod,
                                      std::string_view namespace_name,
                                      uint16_t         port,
                                      std::string_view direction, uint64_t bytes)
{
    if (!initialised_)
        return;
#if defined(KOTA_OTEL) && KOTA_OTEL
    if (impl_ && impl_->packets_dropped_total_counter)
        impl_->packets_dropped_total_counter->Add(
            1, {{"pod", std::string(pod)},
                {"namespace", std::string(namespace_name)},
                {"port", static_cast<std::int64_t>(port)},
                {"direction", std::string(direction)}});
    if (impl_ && impl_->bytes_dropped_total_counter)
        impl_->bytes_dropped_total_counter->Add(
            bytes ? bytes : 1, {{"pod", std::string(pod)},
                                {"namespace", std::string(namespace_name)},
                                {"port", static_cast<std::int64_t>(port)},
                                {"direction", std::string(direction)}});
#endif
}

void OtelExporter::record_lsm_veto_event(std::string_view pod,
                                         std::string_view namespace_name,
                                         std::string_view device,
                                         std::string_view syscall)
{
    if (!initialised_)
        return;
#if defined(KOTA_OTEL) && KOTA_OTEL
    if (impl_ && impl_->lsm_veto_events_total_counter) {
        impl_->lsm_veto_events_total_counter->Add(
            1, {{"pod", std::string(pod)},
                {"namespace", std::string(namespace_name)},
                {"device", std::string(device)},
                {"syscall", std::string(syscall)}});
    }
#endif
}

void OtelExporter::record_verdict_transition(std::string_view pod,
                                             std::string_view namespace_name,
                                             std::string_view from_verdict,
                                             std::string_view to_verdict)
{
    if (!initialised_)
        return;
#if defined(KOTA_OTEL) && KOTA_OTEL
    if (impl_ && impl_->verdict_transitions_total_counter) {
        impl_->verdict_transitions_total_counter->Add(
            1, {{"pod", std::string(pod)},
                {"namespace", std::string(namespace_name)},
                {"from_verdict", std::string(from_verdict)},
                {"to_verdict", std::string(to_verdict)}});
    }
#endif
}

void OtelExporter::record_recovery_event(std::string_view pod,
                                         std::string_view namespace_name)
{
    if (!initialised_)
        return;
#if defined(KOTA_OTEL) && KOTA_OTEL
    if (impl_ && impl_->recovery_events_total_counter) {
        impl_->recovery_events_total_counter->Add(1, {{"pod", std::string(pod)},
                                                      {"namespace", std::string(namespace_name)}});
    }
#endif
}

void OtelExporter::record_bpf_map_update(std::string_view map_name,
                                         std::string_view operation)
{
    if (!initialised_)
        return;
#if defined(KOTA_OTEL) && KOTA_OTEL
    if (impl_ && impl_->bpf_map_updates_total_counter) {
        impl_->bpf_map_updates_total_counter->Add(
            1, {{"map_name", std::string(map_name)},
                {"operation", std::string(operation)}});
    }
#endif
}

void OtelExporter::record_cgroup_event_processed(std::string_view event_type)
{
    if (!initialised_)
        return;
#if defined(KOTA_OTEL) && KOTA_OTEL
    if (impl_ && impl_->cgroup_events_processed_total_counter) {
        impl_->cgroup_events_processed_total_counter->Add(
            1, {{"event_type", std::string(event_type)}});
    }
#endif
}

void OtelExporter::record_identity_resolution_failure(std::string_view reason)
{
    if (!initialised_)
        return;
#if defined(KOTA_OTEL) && KOTA_OTEL
    if (impl_ && impl_->identity_resolution_failures_total_counter) {
        impl_->identity_resolution_failures_total_counter->Add(
            1, {{"reason", std::string(reason)}});
    }
#endif
}

void OtelExporter::record_policy_reload()
{
    if (!initialised_)
        return;
#if defined(KOTA_OTEL) && KOTA_OTEL
    if (impl_ && impl_->policy_reloads_total_counter)
        impl_->policy_reloads_total_counter->Add(1);
#endif
}

void OtelExporter::record_verdict_state(std::string_view pod,
                                        std::string_view namespace_name,
                                        std::int64_t     verdict_state)
{
    if (!initialised_)
        return;
#if defined(KOTA_OTEL) && KOTA_OTEL
    if (impl_ && impl_->verdict_state_gauge) {
        impl_->verdict_state_gauge->Record(
            static_cast<double>(verdict_state),
            {{"pod", std::string(pod)},
             {"namespace", std::string(namespace_name)}},
            opentelemetry::context::Context{});
    }
#endif
}

void OtelExporter::record_nvml_sample(double temperature_c,
                                      std::int64_t utilisation_percent,
                                      double       poll_interval_ms,
                                      bool         memory_error)
{
    if (!initialised_)
        return;
#if defined(KOTA_OTEL) && KOTA_OTEL
    if (impl_ && impl_->nvml_gpu_temp_celsius_gauge)
        impl_->nvml_gpu_temp_celsius_gauge->Record(
            temperature_c, opentelemetry::context::Context{});
    if (impl_ && impl_->nvml_gpu_utilisation_percent_gauge) {
        impl_->nvml_gpu_utilisation_percent_gauge->Record(
            static_cast<double>(utilisation_percent),
            opentelemetry::context::Context{});
    }
    if (impl_ && impl_->nvml_poll_interval_ms_gauge)
        impl_->nvml_poll_interval_ms_gauge->Record(
            poll_interval_ms, opentelemetry::context::Context{});
    if (memory_error && impl_ && impl_->nvml_memory_errors_total_counter)
        impl_->nvml_memory_errors_total_counter->Add(1, {{"device_index", 0}});
#endif
}

void OtelExporter::record_workload_counts(std::int64_t monitored_pods,
                                          std::int64_t enforced_pods)
{
    if (!initialised_)
        return;
#if defined(KOTA_OTEL) && KOTA_OTEL
    if (impl_ && impl_->pods_monitored_total_gauge)
        impl_->pods_monitored_total_gauge->Record(
            static_cast<double>(monitored_pods), opentelemetry::context::Context{});
    if (impl_ && impl_->pods_enforced_total_gauge)
        impl_->pods_enforced_total_gauge->Record(
            static_cast<double>(enforced_pods), opentelemetry::context::Context{});
#endif
}

void OtelExporter::record_active_policies(std::int64_t active_policies)
{
    if (!initialised_)
        return;
#if defined(KOTA_OTEL) && KOTA_OTEL
    if (impl_ && impl_->active_policies_total_gauge)
        impl_->active_policies_total_gauge->Record(
            static_cast<double>(active_policies), opentelemetry::context::Context{});
#endif
}

void OtelExporter::record_uptime_seconds(double uptime_seconds)
{
    if (!initialised_)
        return;
#if defined(KOTA_OTEL) && KOTA_OTEL
    if (impl_ && impl_->uptime_seconds_gauge)
        impl_->uptime_seconds_gauge->Record(
            uptime_seconds, opentelemetry::context::Context{});
#endif
}

} // namespace kota
