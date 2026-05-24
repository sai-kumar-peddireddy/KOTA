#pragma once

#include "kotad_ring_dispatch.h"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace kota {

struct KotadCliOptions {
    bool                        dry_run_telemetry = false;
    std::optional<std::string>  telemetry_profile_path;
};

enum class KotadCliParse { Ok, Help, Error };

KotadCliParse parse_kotad_cli(int argc, char **argv, KotadCliOptions &out);

void print_kotad_help(const char *argv0);

class KotadRuntime {
public:
    explicit KotadRuntime(KotadCliOptions cli);
    ~KotadRuntime();

    KotadRuntime(const KotadRuntime &)            = delete;
    KotadRuntime &operator=(const KotadRuntime &) = delete;

    void request_shutdown() noexcept;

    /** Process exit code. */
    int run();

private:
    KotadCliOptions cli_;

    std::atomic<bool> shutdown_{false};
    /** One-shot: whether we already printed the stdout proof line for drops (not audit trail). */
    std::atomic<bool> stdout_network_drop_proof_logged_{false};
    std::atomic<int>   birth_workers_{0};

    std::mutex                                              enforced_mu_;
    std::unordered_map<std::uint64_t, KotaEnforcedHostRecord> enforced_host_;
};

} // namespace kota
