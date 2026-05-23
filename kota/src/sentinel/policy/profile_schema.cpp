#include "kota_profile.h"

#include <yaml-cpp/yaml.h>

#include <fstream>
#include <sstream>

namespace kota {
namespace {

std::string mark_str(const YAML::Mark &m)
{
    return std::to_string(m.line + 1) + ":" + std::to_string(m.column + 1);
}

std::expected<int, std::string> as_int_in_range(const YAML::Node &n, int lo, int hi,
                                                const char *ctx)
{
    if (!n || !n.IsScalar())
        return std::unexpected(std::string{ctx} + " (expected integer at " +
                               mark_str(n.Mark()) + ")");
    int v = 0;
    try {
        v = n.as<int>();
    } catch (const YAML::Exception &e) {
        return std::unexpected(
            std::string{ctx} + ": bad integer: " + e.what() + " at " +
            mark_str(n.Mark()));
    }
    if (v < lo || v > hi)
        return std::unexpected(
            std::string{ctx} + ": value " + std::to_string(v) +
            " out of range [" + std::to_string(lo) + ".." + std::to_string(hi) +
            "] at " + mark_str(n.Mark()));
    return v;
}

std::expected<std::uint16_t, std::string> as_port(const YAML::Node &n,
                                                    const char *ctx)
{
    auto v = as_int_in_range(n, 1, 65535, ctx);
    if (!v)
        return std::unexpected(v.error());
    return static_cast<std::uint16_t>(*v);
}

std::expected<std::vector<std::uint16_t>, std::string>
parse_port_list(const YAML::Node &n, const char *ctx)
{
    if (!n || !n.IsSequence())
        return std::unexpected(
            std::string{ctx} + " (expected a sequence) at " + mark_str(n.Mark()));
    std::vector<std::uint16_t> out;
    for (const auto &el : n) {
        if (auto p = as_port(el, ctx))
            out.push_back(*p);
        else
            return std::unexpected(p.error());
    }
    return out;
}

std::expected<std::uint32_t, std::string> parse_ioctl_cmd_scalar(const YAML::Node &n,
                                                                  const char *ctx)
{
    if (!n || !n.IsScalar())
        return std::unexpected(std::string{ctx} + " (expected scalar) at " +
                               mark_str(n.Mark()));
    const std::string raw = n.as<std::string>();
    try {
        size_t idx = 0;
        unsigned long v = std::stoul(raw, &idx, 0);
        if (idx != raw.size())
            return std::unexpected(std::string{ctx} + ": invalid value `" + raw +
                                   "` at " + mark_str(n.Mark()));
        if (v > 0xffffffffUL)
            return std::unexpected(std::string{ctx} + ": value out of u32 range `" +
                                   raw + "` at " + mark_str(n.Mark()));
        return static_cast<std::uint32_t>(v);
    } catch (const std::exception &) {
        return std::unexpected(std::string{ctx} + ": invalid value `" + raw +
                               "` at " + mark_str(n.Mark()));
    }
}

std::expected<std::vector<std::uint32_t>, std::string>
parse_ioctl_cmd_list(const YAML::Node &n, const char *ctx)
{
    if (!n || !n.IsSequence())
        return std::unexpected(
            std::string{ctx} + " (expected a sequence) at " + mark_str(n.Mark()));
    std::vector<std::uint32_t> out;
    for (const auto &el : n) {
        auto cmd = parse_ioctl_cmd_scalar(el, ctx);
        if (!cmd)
            return std::unexpected(cmd.error());
        out.push_back(*cmd);
    }
    return out;
}

void parse_nvml_block(KotaNvmlPolicy *out, const YAML::Node &root, std::string *err,
                      const char *file_ctx)
{
    const YAML::Node nv = root["nvml"];
    if (!nv || !nv.IsMap() || out == nullptr)
        return;

    if (const YAML::Node t = nv["max_temperature_c"]) {
        if (!t.IsScalar()) {
            if (err && err->empty())
                *err = std::string{file_ctx} + ": nvml.max_temperature_c must be "
                                                "a number at " +
                       std::to_string(t.Mark().line + 1) + ":" +
                       std::to_string(t.Mark().column + 1);
        } else {
            try {
                out->max_temperature_c = t.as<double>();
            } catch (const YAML::Exception &e) {
                if (err && err->empty())
                    *err = std::string{file_ctx} + ": nvml.max_temperature_c: " +
                           e.what();
            }
        }
    }

    if (const YAML::Node m = nv["memory_error_causes_violation"]) {
        if (!m.IsScalar()) {
            if (err && err->empty())
                *err = std::string{file_ctx} +
                       ": nvml.memory_error_causes_violation must be a bool at " +
                       std::to_string(m.Mark().line + 1) + ":" +
                       std::to_string(m.Mark().column + 1);
        } else {
            try {
                out->memory_error_causes_violation = m.as<bool>();
            } catch (const YAML::Exception &e) {
                if (err && err->empty())
                    *err = std::string{file_ctx} +
                           ": nvml.memory_error_causes_violation: " + e.what();
            }
        }
    }
}

} // namespace

std::expected<KotaProfile, std::string>
load_kota_profile_yaml(const std::filesystem::path &path)
{
    std::ifstream f(path);
    if (!f)
        return std::unexpected("cannot open profile YAML: " + path.string());
    std::ostringstream buf;
    buf << f.rdbuf();
    return load_kota_profile_yaml_string(buf.str(), path.string());
}

std::expected<KotaProfile, std::string>
load_kota_profile_yaml_string(const std::string &source,
                              const std::string &label_for_errors)
{
    YAML::Node root;
    try {
        root = YAML::Load(source);
    } catch (const YAML::Exception &e) {
        return std::unexpected("YAML parse error in " + label_for_errors + ": " +
                               std::string(e.what()) + " (line " +
                               std::to_string(e.mark.line + 1) + ")");
    }

    if (!root.IsMap())
        return std::unexpected("profile " + label_for_errors +
                               ": top level must be a mapping");

    if (!root["version"] || !root["version"].IsScalar())
        return std::unexpected("profile " + label_for_errors +
                               ": `version` (scalar) is required");

    int ver = 0;
    try {
        ver = root["version"].as<int>();
    } catch (const YAML::Exception &e) {
        return std::unexpected("profile " + label_for_errors + ": version: " +
                               std::string(e.what()));
    }
    if (ver != 1)
        return std::unexpected("profile " + label_for_errors +
                               ": unsupported schema version " +
                               std::to_string(ver) + " (CE supports 1)");

    if (!root["name"] || !root["name"].IsScalar())
        return std::unexpected("profile " + label_for_errors +
                               ": `name` (string) is required");

    KotaProfile pr{};
    pr.schema_version = static_cast<std::uint32_t>(ver);
    try {
        pr.name = root["name"].as<std::string>();
    } catch (const YAML::Exception &e) {
        return std::unexpected("profile " + label_for_errors + ": name: " + e.what());
    }
    if (pr.name.empty())
        return std::unexpected("profile " + label_for_errors +
                               ": `name` must be non-empty");

    const YAML::Node mp = root["management_ports"];
    if (auto pl = parse_port_list(mp, "management_ports")) {
        pr.management_ports = std::move(*pl);
    } else {
        return std::unexpected("profile " + label_for_errors + ": " + pl.error());
    }

    const YAML::Node ap =
        root["ai_data_ports"] ? root["ai_data_ports"] : root["ai_ports"];
    if (ap) {
        if (auto pl = parse_port_list(ap, "ai_data_ports (or ai_ports)")) {
            pr.ai_data_ports = std::move(*pl);
        } else {
            return std::unexpected("profile " + label_for_errors + ": " + pl.error());
        }
    }

    std::string nvml_err;
    parse_nvml_block(&pr.nvml, root, &nvml_err, label_for_errors.c_str());
    if (!nvml_err.empty())
        return std::unexpected(nvml_err);

    if (const YAML::Node io = root["ioctl_policy"]; io) {
        if (!io.IsMap())
            return std::unexpected("profile " + label_for_errors +
                                   ": ioctl_policy must be a mapping");
        if (const YAML::Node deny = io["deny_cmds_hex"]; deny) {
            auto parsed = parse_ioctl_cmd_list(deny, "ioctl_policy.deny_cmds_hex");
            if (!parsed)
                return std::unexpected("profile " + label_for_errors + ": " +
                                       parsed.error());
            pr.blocked_ioctl_cmds = std::move(*parsed);
        }
    }

    return pr;
}

} // namespace kota
