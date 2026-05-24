#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

namespace kota {

class CiliumPeeker {
public:
    static constexpr std::string_view kCiliumBpfPath = "/sys/fs/bpf/cilium";

    CiliumPeeker();

    bool is_available() const;

    std::expected<uint32_t, std::string> get_security_id(std::string_view pod_ip);

private:
    bool available_;
    int  ipcache_fd_ = -1;
    std::string ipcache_path_;
    std::string unavailable_reason_;
    bool logged_unavailable_reason_ = false;
    bool logged_lookup_miss_reason_ = false;
};

} // namespace kota
