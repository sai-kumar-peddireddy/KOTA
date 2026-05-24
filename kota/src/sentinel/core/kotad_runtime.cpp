/*
 * kotad runtime — BPF sentinel lifecycle (docs/flow.md).
 */

#include "kotad_runtime.h"

#include "control_plane_server.h"
#include "kotad_nvml_monitor.h"
#include "kotad_ring_dispatch.h"

#include <atomic>
#include <array>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <expected>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <grpcpp/grpcpp.h>

#include "../maps/bpf_loader.h"
#include "../identity/cilium_peeker.h"
#include "../identity/pod_resolver.h"
#include "../identity/ringbuf_consumer.h"
#include "../maps/kota_bpf_user_abi.h"
#include "../policy/profile_registry.h"
#include "../policy/kota_profile.h"
#include "../policy/profile_store.h"
#include "../telemetry/nvml_poller.h"
#include "../telemetry/otel_exporter.h"
#include "../telemetry/violation_logger.h"
#include "../../../include/shared/kota_common.h"

namespace kota {

namespace {

KotadRuntime *g_signal_target = nullptr;

void signal_handler(int /*sig*/)
{
    if (g_signal_target != nullptr)
        g_signal_target->request_shutdown();
}

/**
 * RAII: bind SIGINT/SIGTERM to request_shutdown() and publish g_signal_target.
 * Does not restore prior handlers (typical daemon lifetime); clears target only.
 */
struct ScopedDaemonSignals {
    KotadRuntime *runtime_;

    explicit ScopedDaemonSignals(KotadRuntime *r) : runtime_(r)
    {
        g_signal_target = r;
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);
    }

    ScopedDaemonSignals(const ScopedDaemonSignals &)            = delete;
    ScopedDaemonSignals &operator=(const ScopedDaemonSignals &) = delete;

    ~ScopedDaemonSignals()
    {
        if (g_signal_target == runtime_)
            g_signal_target = nullptr;
    }
};

std::optional<long> env_to_long(const char *name)
{
    const char *e = std::getenv(name);
    if (!e || !*e)
        return std::nullopt;
    char *end = nullptr;
    errno = 0;
    const long v = std::strtol(e, &end, 10);
    if (errno != 0 || end == e || (end && *end != '\0'))
        return std::nullopt;
    return v;
}

std::optional<double> env_to_double(const char *name)
{
    const char *e = std::getenv(name);
    if (!e || !*e)
        return std::nullopt;
    char *end = nullptr;
    errno = 0;
    const double v = std::strtod(e, &end);
    if (errno != 0 || end == e || (end && *end != '\0'))
        return std::nullopt;
    return v;
}

NvmlPollerConfig telemetry_config_from_env()
{
    NvmlPollerConfig cfg{};
    if (const auto ms = env_to_long("KOTA_NVML_POLL_MS"); ms && *ms > 0)
        cfg.poll_interval = std::chrono::milliseconds(*ms);
    if (const auto v = env_to_long("KOTA_NVML_DEBOUNCE_VIOLATION"); v && *v > 0)
        cfg.violation_debounce_samples = static_cast<std::uint32_t>(*v);
    if (const auto c = env_to_long("KOTA_NVML_DEBOUNCE_CLEAR"); c && *c > 0)
        cfg.clear_debounce_samples = static_cast<std::uint32_t>(*c);
    return cfg;
}

void log_nvml_sample_line(const GpuHealthSample &s, kota_decide stable)
{
    std::cout << "[KOTA] NVML sample temp="
              << (s.have_temperature ? std::to_string(s.temperature_c) : "n/a")
              << "C mem_error=" << (s.memory_error ? "1" : "0") << " stable="
              << (stable == kota_decide::active ? "ACTIVE" : "VIOLATION") << '\n';
}

void apply_nvml_test_max_temp_override(KotaProfile &profile)
{
    if (const auto max_override = env_to_double("KOTA_NVML_TEST_MAX_TEMP_C")) {
        profile.nvml.max_temperature_c = *max_override;
        std::cout << "[KOTA] telemetry threshold override: max_temperature_c="
                  << *max_override << '\n';
    }
}

std::filesystem::path profile_store_root_from_env()
{
    if (const char *pd = std::getenv("KOTA_PROFILE_DIR"); pd && *pd)
        return std::filesystem::path{pd};
    std::error_code pe;
    if (std::filesystem::exists("deploy/profiles", pe))
        return "deploy/profiles";
    return "/etc/kota/profiles";
}

std::expected<KotaProfile, std::string>
load_telemetry_profile(const std::optional<std::string> &arg_path,
                       const ProfileStore             &profile_store)
{
    auto try_load = [](const std::filesystem::path &p)
        -> std::expected<KotaProfile, std::string> {
        std::error_code ec;
        if (!std::filesystem::exists(p, ec))
            return std::unexpected("profile not found: " + p.string());
        return load_kota_profile_yaml(p);
    };

    if (arg_path && !arg_path->empty()) {
        auto r = try_load(*arg_path);
        if (r)
            return *r;
        return std::unexpected("telemetry profile argument invalid: " + r.error());
    }
    if (const char *ep = std::getenv("KOTA_TELEMETRY_PROFILE"); ep && *ep) {
        auto r = try_load(ep);
        if (r)
            return *r;
        return std::unexpected("KOTA_TELEMETRY_PROFILE invalid: " + r.error());
    }

    const std::array<std::filesystem::path, 3> candidates{
        profile_store.root() / "1.yaml",
        std::filesystem::path{"tests/fixtures/profiles/valid_profile.yaml"},
        std::filesystem::path{"deploy/sample-profile.yaml"},
    };
    for (const auto &candidate : candidates) {
        if (auto p = try_load(candidate))
            return p;
    }

    KotaProfile fallback{};
    fallback.schema_version = 1;
    fallback.name = "telemetry-fallback";
    fallback.nvml.max_temperature_c = 90.0;
    fallback.nvml.memory_error_causes_violation = true;
    return fallback;
}

} // namespace

void KotadRuntime::request_shutdown() noexcept
{
    shutdown_.store(true, std::memory_order_relaxed);
}

KotadCliParse parse_kotad_cli(int argc, char **argv, KotadCliOptions &out)
{
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--help") == 0)
            return KotadCliParse::Help;
        else if (std::strcmp(argv[i], "--dry-run-telemetry") == 0)
            out.dry_run_telemetry = true;
        else if (std::strcmp(argv[i], "--telemetry-profile") == 0 && i + 1 < argc)
            out.telemetry_profile_path = argv[++i];
        else {
            std::cerr << "[KOTA] unknown argument: " << argv[i] << '\n';
            return KotadCliParse::Error;
        }
    }
    return KotadCliParse::Ok;
}

void print_kotad_help(const char *argv0)
{
    std::cout
        << "Usage: " << argv0 << " [options]\n"
        << "Options:\n"
        << "  --help                  Show this help and exit\n"
        << "  --dry-run-telemetry     Run NVML telemetry loop in dry-run mode\n"
        << "  --telemetry-profile P   YAML profile path for telemetry mode\n"
        << "\n"
        << "Enforcement (TCX Scalpel + LSM veto) follows docs/HLD.md / LLD.md: per-pod "
           "TCX on resolved lxc* is always on; LSM attaches when the kernel exposes "
           "bpf in /sys/kernel/security/lsm. Opt-out: KOTA_DISABLE_LSM=1. Optional lab "
           "boot TCX on one iface: KOTA_TCX_IF (legacy KOTA_SMOKE_TCX_IF).\n"
        << "Pod identity: KOTA_CILIUM_UDS_RETRY_SLEEP_MS (0–250, default 15) wait before "
           "second Cilium UDS try on miss. KOTA_QUIET_TCX_ATTACH=1 skips successful TCX "
           "stdout lines.\n";
}

KotadRuntime::KotadRuntime(KotadCliOptions cli) : cli_(std::move(cli)) {}

KotadRuntime::~KotadRuntime()
{
    if (g_signal_target == this)
        g_signal_target = nullptr;
}

int KotadRuntime::run()
{
    std::cout << "[KOTA] kotad (Community Edition) starting\n";

    const ScopedDaemonSignals sig_scope{this};

    BpfLoader loader{BpfConfig{
        .bpffs_path         = "/sys/fs/bpf/kota",
        .status_map_size    = KOTA_DEFAULT_STATUS_MAP_ENTRIES,
        .profile_map_size   = 256,
        .telemetry_size     = 16384,
        .ip_to_inode_size   = KOTA_DEFAULT_IP_TO_INODE_ENTRIES,
        .ringbuf_size_bytes = 16 * 1024 * 1024,
    }};

    auto load_result = loader.load();
    const bool bpf_ok = load_result.has_value();
    if (!load_result)
        std::cerr << "[KOTA] BPF load failed: " << load_result.error() << '\n';

    ProfileRegistry profiles{loader.map_fd(KOTA_MAP_PROFILE_MAP),
                             loader.map_fd(KOTA_MAP_POLICY_PORTS),
                             loader.map_fd(KOTA_MAP_POLICY_IOCTL)};
    if (auto res = profiles.load_defaults(); !res)
        std::cerr << "[KOTA] ProfileRegistry: " << res.error() << '\n';

    ProfileStore profile_store{profile_store_root_from_env()};
    ProfileStore control_store{ProfileStore::default_data_root()};

    std::unique_ptr<grpc::Server> control_server;
    std::string control_socket_path;
    const bool disable_control_sock =
        []() {
            const char *e = std::getenv("KOTA_DISABLE_CONTROL_SOCK");
            return e && (e[0] == '1' || e[0] == 't' || e[0] == 'T' || e[0] == 'y' ||
                         e[0] == 'Y');
        }();
    if (!disable_control_sock) {
        auto socket_path = control_socket_path_from_env();
        if (!socket_path) {
            std::cerr << "[KOTA] control socket disabled: " << socket_path.error() << '\n';
        } else {
            control_socket_path = *socket_path;
            auto server_or = start_control_plane_server(
                control_socket_path,
                ControlPlaneCallbacks{
                    .apply_policy =
                        [&](const std::string &policy_yaml)
                        -> std::expected<std::string, std::string> {
                        auto parsed = load_kota_profile_yaml_string(policy_yaml, "ApplyPolicy");
                        if (!parsed)
                            return std::unexpected(parsed.error());
                        if (parsed->name.empty())
                            return std::unexpected("policy name cannot be empty");

                        if (auto persist = control_store.upsert_policy_yaml(parsed->name, policy_yaml);
                            !persist) {
                            return std::unexpected(persist.error());
                        }
                        if (auto reload = profiles.load_defaults(); !reload) {
                            return std::unexpected("reload failed: " + reload.error());
                        }
                        return parsed->name;
                    },
                    .get_status_rows =
                        [&]() -> std::vector<ControlStatusRow> {
                        std::vector<ControlStatusRow> rows;
                        std::lock_guard<std::mutex> lock(enforced_mu_);
                        for (const auto &[inode, rec] : enforced_host_) {
                            struct kota_status_map_value sv{};
                            if (bpf_map_lookup_elem(loader.map_fd(KOTA_MAP_STATUS_MAP), &inode, &sv) != 0)
                                continue;
                            ControlStatusRow row{};
                            row.workload_key = std::to_string(inode);
                            row.namespace_name = rec.namespace_name;
                            row.pod_name = rec.pod_name;
                            row.profile = std::to_string(sv.profile_id);
                            row.verdict = (sv.verdict == KOTA_VERDICT_VIOLATION) ? "VIOLATION" : "ACTIVE";
                            row.armed = (sv.profile_id != 0U);
                            rows.push_back(std::move(row));
                        }
                        return rows;
                    },
                });
            if (!server_or) {
                std::cerr << "[KOTA] control socket disabled: " << server_or.error() << '\n';
            } else {
                control_server = std::move(*server_or);
            }
        }
    } else {
        std::cout << "[KOTA] control socket disabled by KOTA_DISABLE_CONTROL_SOCK=1\n";
    }

    if (cli_.dry_run_telemetry) {
        std::cout << "[KOTA] telemetry dry-run mode\n";
        auto profile =
            load_telemetry_profile(cli_.telemetry_profile_path, profile_store);
        if (!profile) {
            std::cerr << "[KOTA] telemetry profile load failed: " << profile.error()
                      << " (dry-run exits 0)\n";
            return 0;
        }
        apply_nvml_test_max_temp_override(*profile);

        const NvmlPollerConfig poll_cfg = telemetry_config_from_env();
        NvmlPoller poller{poll_cfg, log_nvml_sample_line};

        if (auto r = poller.init(); !r) {
            std::cerr << "[KOTA] telemetry dry-run: NVML unavailable: " << r.error()
                      << " (exits 0)\n";
            return 0;
        }

        const auto iterations = env_to_long("KOTA_NVML_DRY_RUN_ITERS").value_or(4);
        for (long i = 0; i < iterations; ++i) {
            auto step = poller.poll_once(*profile);
            if (!step) {
                std::cerr << "[KOTA] telemetry dry-run poll: " << step.error()
                          << " (exits 0)\n";
                return 0;
            }
            if (step->has_value()) {
                std::cout << "[KOTA] NVML debounced transition -> "
                          << (step->value() == kota_decide::active ? "ACTIVE"
                                                                     : "VIOLATION")
                          << '\n';
            }
            std::this_thread::sleep_for(poll_cfg.poll_interval);
        }
        std::cout << "[KOTA] telemetry dry-run complete\n";
        return 0;
    }

    CiliumPeeker cilium{};

    PodResolver resolver{loader.map_fd(KOTA_MAP_STATUS_MAP),
                         loader.map_fd(KOTA_MAP_IP_TO_INODE),
                         loader.map_fd(KOTA_MAP_CGROUP_BRIDGE),
                         loader.map_fd(KOTA_MAP_NETNS_STATUS),
                         "/run/containerd/containerd.sock",
                         &profiles};

    ViolationLogger vlogger{};
    if (auto res = vlogger.open("/var/log/kota/violations.jsonl"); !res)
        std::cerr << "[KOTA] ViolationLogger: " << res.error() << " (non-fatal)\n";

    OtelExporter otel{};
    if (auto res = otel.init(std::string_view{}); !res)
        std::cerr << "[KOTA] OtelExporter: " << res.error() << " (non-fatal)\n";
    else {
        otel.record_policy_reload();
        otel.record_active_policies(1);
    }

    auto telemetry_profile =
        load_telemetry_profile(cli_.telemetry_profile_path, profile_store);
    if (!telemetry_profile) {
        std::cerr << "[KOTA] telemetry profile load failed: "
                  << telemetry_profile.error() << '\n';
    } else {
        apply_nvml_test_max_temp_override(*telemetry_profile);
    }

    const NvmlPollerConfig nvml_poll_cfg = telemetry_config_from_env();
    std::jthread         monitor_thread{[&loader, &otel, this, nvml_poll_cfg,
                                 profile = std::move(telemetry_profile)](
                                    std::stop_token st) mutable {
        run_kotad_nvml_monitor_loop(st, loader, otel, this->enforced_mu_,
                                  this->enforced_host_, nvml_poll_cfg,
                                  log_nvml_sample_line,
                                  std::move(profile));
    }};

    const int events_fd = loader.map_fd(KOTA_MAP_EVENTS);
    std::optional<KotadRingDispatcher> ring_dispatch;
    std::optional<RingBufConsumer>     consumer;
    std::optional<std::jthread>        rb_thread;

    if (events_fd >= 0 && bpf_ok) {
        ring_dispatch.emplace(resolver, profile_store, cilium, vlogger, otel,
                              loader.map_fd(KOTA_MAP_STATUS_MAP),
                              loader.map_fd(KOTA_MAP_CGROUP_BRIDGE),
                              stdout_network_drop_proof_logged_, birth_workers_,
                              enforced_mu_, enforced_host_);
        consumer.emplace(
            events_fd,
            [&ring_dispatch](const kota_event &ev) { ring_dispatch->dispatch(ev); });
        rb_thread.emplace([&](std::stop_token st) {
            if (auto res = consumer->run(std::move(st)); !res)
                std::cerr << "[KOTA] RingBufConsumer: " << res.error() << '\n';
        });
    } else {
        std::cout << "[KOTA] Ring buffer consumer not started (no events map fd)\n";
    }

    std::cout << "[KOTA] kotad running — SIGTERM or SIGINT to stop\n";
    const auto started_at = std::chrono::steady_clock::now();

    while (!shutdown_.load(std::memory_order_relaxed)) {
        const auto uptime_seconds =
            std::chrono::duration_cast<std::chrono::duration<double>>(
                std::chrono::steady_clock::now() - started_at)
                .count();
        otel.record_uptime_seconds(uptime_seconds);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << "[KOTA] kotad shutdown initiated\n";

    if (rb_thread.has_value())
        rb_thread->request_stop();
    monitor_thread.request_stop();
    if (control_server) {
        control_server->Shutdown();
        cleanup_control_socket_file(control_socket_path);
    }

    otel.shutdown();
    vlogger.close();

    for (int w = 0; w < 200 && birth_workers_.load(std::memory_order_relaxed) > 0;
         ++w)
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    if (birth_workers_.load(std::memory_order_relaxed) > 0)
        std::cerr << "[KOTA] shutdown: timed out waiting for birth workers\n";

    {
        std::lock_guard<std::mutex> lock(enforced_mu_);
        for (auto &kv : enforced_host_) {
            if (!kv.second.pod_ip.empty())
                static_cast<void>(
                    resolver.remove_ip_attribution(kv.second.pod_ip));
        }
        enforced_host_.clear();
    }

    loader.unload();

    std::cout << "[KOTA] kotad stopped\n";
    return 0;
}

} // namespace kota
