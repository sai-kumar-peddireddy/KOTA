#pragma once

#include <cstdint>
#include <expected>
#include <map>
#include <string>
#include <string_view>

namespace kota {

class ProfileRegistry {
public:
    explicit ProfileRegistry(int profile_map_fd, int policy_ports_map_fd = -1,
                             int policy_ioctl_map_fd = -1);

    std::expected<void, std::string> load_defaults();

    std::expected<uint32_t, std::string>
    get_profile_id(std::string_view name) const;

    uint32_t count() const
    {
        return static_cast<uint32_t>(name_to_id_.size());
    }

private:
    int                             profile_map_fd_;
    int                             policy_ports_map_fd_;
    int                             policy_ioctl_map_fd_;
    std::map<std::string, uint32_t> name_to_id_;
};

} // namespace kota
