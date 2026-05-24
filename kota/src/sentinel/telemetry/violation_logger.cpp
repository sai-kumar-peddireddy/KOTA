#include "violation_logger.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <format>
#include <iostream>
#include <string>

namespace kota {

namespace {

bool is_violation_or_network_event(uint32_t t)
{
    switch (t) {
    case KOTA_EVT_NETWORK_DROP:
    case KOTA_EVT_NETWORK_AUDIT:
    case KOTA_EVT_IOCTL_BLOCK:
    case KOTA_EVT_IOCTL_AUDIT:
    case KOTA_EVT_MMAP_BLOCK:
    case KOTA_EVT_MMAP_AUDIT:
    case KOTA_EVT_INGRESS_DROP:
    case KOTA_EVT_QUARANTINE_DROP:
    case KOTA_EVT_FAILSAFE_FIRED:
    case KOTA_EVT_FAILSAFE_AUDIT:
    case KOTA_EVT_LICENSE_EXPIRED:
        return true;
    default:
        return false;
    }
}

bool should_log_ioctl_event(const kota_event &event)
{
    if (event.event_type == KOTA_EVT_IOCTL_BLOCK)
        return true;
    if (event.event_type != KOTA_EVT_IOCTL_AUDIT)
        return true;
    /* Drop observer-noise audits from unmanaged/unknown callers. */
    if (event.profile_id == 0 &&
        (event.verdict_reason == 40 || event.verdict_reason == 41 ||
         event.verdict_reason == 20 || event.verdict_reason == 21))
        return false;
    return true;
}

std::string ipv4_to_dotted(uint32_t be)
{
    struct in_addr a{};
    a.s_addr = be;
    char buf[INET_ADDRSTRLEN]{};
    if (inet_ntop(AF_INET, &a, buf, sizeof(buf)) == nullptr)
        return "0.0.0.0";
    return std::string{buf};
}

} // namespace

ViolationLogger::~ViolationLogger() { close(); }

std::expected<void, std::string> ViolationLogger::open(std::string_view log_path)
{
    close();
    const std::string path{log_path};
    fd_ = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd_ < 0) {
        return std::unexpected(std::string("open ") + path + ": " +
                               std::strerror(errno));
    }
    open_ = true;
    std::cout << "[KOTA] ViolationLogger: writing " << path << '\n';
    return {};
}

void ViolationLogger::log_event(const kota_event &event)
{
    if (!open_ || fd_ < 0)
        return;
    if (!is_violation_or_network_event(event.event_type))
        return;
    if (!should_log_ioctl_event(event))
        return;

    const std::string line = std::format(
        R"({{"ts_ns":{},"event_type":{},"cgroup_inode":{},"seq_no":{},"pid":{},"saddr_v4":"{}","daddr_v4":"{}","ioctl_cmd":{},"profile_id":{},"sport":{},"dport":{},"protocol":{},"verdict_reason":{}}})"
        "\n",
        event.timestamp_ns,
        event.event_type,
        event.cgroup_inode,
        event.seq_no,
        event.pid,
        ipv4_to_dotted(event.saddr_v4),
        ipv4_to_dotted(event.daddr_v4),
        event.ioctl_cmd,
        event.profile_id,
        event.sport,
        event.dport,
        event.protocol,
        event.verdict_reason);

    const char *p   = line.data();
    size_t left     = line.size();
    while (left > 0) {
        const ssize_t n = ::write(fd_, p, left);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            std::cerr << "[KOTA] ViolationLogger: write: " << std::strerror(errno)
                      << '\n';
            return;
        }
        if (n == 0)
            return;
        p += static_cast<size_t>(n);
        left -= static_cast<size_t>(n);
    }
    static_cast<void>(::fdatasync(fd_));
}

void ViolationLogger::close()
{
    if (!open_ && fd_ < 0)
        return;
    if (fd_ >= 0) {
        static_cast<void>(::fsync(fd_));
        static_cast<void>(::close(fd_));
        fd_ = -1;
    }
    open_ = false;
}

} // namespace kota
