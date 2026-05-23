#pragma once

#include <expected>
#include <functional>
#include <stop_token>
#include <string>

#include "../maps/kota_bpf_user_abi.h"

namespace kota {

class RingBufConsumer {
public:
    using EventCallback = std::function<void(const kota_event &)>;

    explicit RingBufConsumer(int events_map_fd, EventCallback cb);
    ~RingBufConsumer();

    std::expected<void, std::string> run(std::stop_token st);

private:
    int           events_map_fd_;
    EventCallback cb_;
};

} // namespace kota
