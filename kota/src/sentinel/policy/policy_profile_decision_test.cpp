/*
 * Unit tests: YAML profile schema + decision engine (parse + verdict enum).
 * Built as target `policy_profile_decision_test`; run
 * `ctest -R policy_profile_decision` from the build tree.
 */
#include "kota_profile.h"

#include "../../../include/shared/kota_common.h"

#include <cstdlib>
#include <iostream>
#include <string>

using namespace kota;

namespace {

#define FAIL(m)                                                                 \
    do {                                                                        \
        std::cerr << "[policy_profile_decision] FAIL: " << (m) << '\n';         \
        return false;                                                         \
    } while (0)

bool run()
{
    const std::string root = KOTA_POLICY_PROFILE_FIXTURE_ROOT;

    {
        const auto p = load_kota_profile_yaml(root + "/valid_profile.yaml");
        if (!p)
            FAIL(p.error().c_str());
        if (p->schema_version != 1u || p->name != "Inference-Only")
            FAIL("profile name / version");
        if (p->management_ports.size() != 3u || p->ai_data_ports.size() != 2u)
            FAIL("port list sizes");
        if (!p->nvml.max_temperature_c || *p->nvml.max_temperature_c != 90.0)
            FAIL("nvml max_temperature_c");
    }

    {
        const auto e = load_kota_profile_yaml(root + "/bad_version.yaml");
        if (e)
            FAIL("expected reject bad_version");
    }

    {
        const auto e =
            load_kota_profile_yaml_string("][\n", "inline-mismatch");
        if (e)
            FAIL("expected YAML parse error");
    }

    {
        const auto e = load_kota_profile_yaml(root + "/bad_nvml_type.yaml");
        if (e)
            FAIL("expected invalid nvml");
    }

    {
        KotaProfile pr{};
        pr.name = "t";
        pr.schema_version = 1;
        pr.nvml.max_temperature_c = 50.0;
        GpuTelemetrySample cool{};
        cool.have_temperature  = true;
        cool.temperature_c   = 40.0;
        if (decide_from_gpu_telemetry(pr, cool) != kota_decide::active)
            FAIL("expect ACTIVE below threshold");
        if (verdict_from_decision(decide_from_gpu_telemetry(pr, cool)) !=
            KOTA_VERDICT_ACTIVE)
            FAIL("verdict active");

        GpuTelemetrySample hot = cool;
        hot.temperature_c      = 99.0;
        if (decide_from_gpu_telemetry(pr, hot) != kota_decide::violation)
            FAIL("expect VIOLATION over threshold");
        if (verdict_from_decision(decide_from_gpu_telemetry(pr, hot)) !=
            KOTA_VERDICT_VIOLATION)
            FAIL("verdict violation");

        pr.nvml.max_temperature_c.reset();
        pr.nvml.memory_error_causes_violation = true;
        GpuTelemetrySample mem{};
        mem.have_memory_error = true;
        mem.memory_error      = true;
        if (decide_from_gpu_telemetry(pr, mem) != kota_decide::violation)
            FAIL("expect VIOLATION on memory error when enabled");
    }

    std::cout << "[policy_profile_decision] schema + decision: OK\n";
    return true;
}

} // namespace

int main()
{
    return run() ? 0 : 1;
}
