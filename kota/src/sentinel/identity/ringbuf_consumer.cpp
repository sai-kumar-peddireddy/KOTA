#include "ringbuf_consumer.h"

#include <bpf/libbpf.h>
#include <cerrno>
#include <iostream>
#include <memory>
#include <string>

namespace kota {

namespace {

int handle_event(void *ctx, void *data, size_t data_sz)
{
    if (data_sz < sizeof(kota_event))
        return 0;
    auto *cb = static_cast<RingBufConsumer::EventCallback *>(ctx);
    (*cb)(*static_cast<const kota_event *>(data));
    return 0;
}

} // namespace

RingBufConsumer::RingBufConsumer(int events_map_fd, EventCallback cb)
    : events_map_fd_(events_map_fd), cb_(std::move(cb))
{}

RingBufConsumer::~RingBufConsumer() = default;

std::expected<void, std::string> RingBufConsumer::run(std::stop_token st)
{
    if (events_map_fd_ < 0)
        return std::unexpected{"events map not available (BPF not loaded)"};

    auto rb_deleter = [](ring_buffer *rb) { ring_buffer__free(rb); };
    std::unique_ptr<ring_buffer, decltype(rb_deleter)> rb{
        ring_buffer__new(events_map_fd_, handle_event, &cb_, nullptr),
        rb_deleter};

    if (!rb) {
        return std::unexpected(
            std::string("ring_buffer__new failed (events_fd=") +
            std::to_string(events_map_fd_) + ')');
    }

    std::cout << "[KOTA] RingBufConsumer: started (events_fd=" << events_map_fd_
              << ")\n";

    while (!st.stop_requested()) {
        int err = ring_buffer__poll(rb.get(), 100);
        if (err < 0 && err != -EINTR) {
            return std::unexpected(std::string("ring_buffer__poll error: ") +
                                   std::to_string(err));
        }
    }

    std::cout << "[KOTA] RingBufConsumer: stopped\n";
    return {};
}

} // namespace kota
