#pragma once

#include <expected>
#include <string>
#include <string_view>

#include "../maps/kota_bpf_user_abi.h"

namespace kota {

class ViolationLogger {
public:
    ViolationLogger() = default;
    ~ViolationLogger();

    std::expected<void, std::string> open(std::string_view log_path);

    void log_event(const kota_event &event);

    void close();

private:
    int  fd_   = -1;
    bool open_ = false;
};

} // namespace kota
