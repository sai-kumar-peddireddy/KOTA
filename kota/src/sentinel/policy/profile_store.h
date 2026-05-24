#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <vector>

namespace kota {

struct StoredPolicyRecord {
    std::string id;
    std::string yaml;
    std::int64_t updated_at_unix = 0;
};

/**
 * Maps numeric profile_id to on-disk YAML path .
 * Conventions: root / "<id>.yaml".
 */
class ProfileStore {
public:
    explicit ProfileStore(std::filesystem::path root_dir);

    static std::filesystem::path default_data_root();

    std::expected<std::filesystem::path, std::string>
    yaml_path_for(uint32_t profile_id) const;

    std::expected<void, std::string> upsert_policy_yaml(std::string policy_id,
                                                        std::string policy_yaml) const;

    std::expected<std::vector<StoredPolicyRecord>, std::string>
    list_policies() const;

    std::filesystem::path sqlite_db_path() const;

    const std::filesystem::path &root() const { return root_dir_; }

private:
    std::filesystem::path root_dir_;
};

} // namespace kota
