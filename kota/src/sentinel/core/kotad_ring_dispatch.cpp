#include "kotad_ring_dispatch.h"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <sys/stat.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>

#include "../identity/cilium_peeker.h"
#include "../identity/pod_resolver.h"
#include "../policy/profile_store.h"
#include "../telemetry/otel_exporter.h"
#include "../telemetry/violation_logger.h"

namespace kota {

namespace {

bool debug_ring_violations()
{
    const char *e = std::getenv("KOTA_DEBUG_RING_VIOLATIONS");
    return e && (e[0] == '1' || e[0] == 't' || e[0] == 'T');
}

bool debug_ioctl_bridge()
{
    const char *e = std::getenv("KOTA_DEBUG_IOCTL_BRIDGE");
    return e && (e[0] == '1' || e[0] == 't' || e[0] == 'T');
}

/** RAII: increments birth worker count for detached birth threads. */
class BirthWorkerSlot {
public:
    explicit BirthWorkerSlot(std::atomic<int> &n) noexcept : n_(&n)
    {
        n_->fetch_add(1, std::memory_order_relaxed);
    }
    BirthWorkerSlot(const BirthWorkerSlot &)            = delete;
    BirthWorkerSlot &operator=(const BirthWorkerSlot &) = delete;
    ~BirthWorkerSlot()
    {
        n_->fetch_sub(1, std::memory_order_relaxed);
    }

private:
    std::atomic<int> *n_;
};

} // namespace

KotadRingDispatcher::KotadRingDispatcher(
    PodResolver                    &resolver,
    ProfileStore                   &profile_store,
    CiliumPeeker                   &cilium,
    ViolationLogger                &vlogger,
    OtelExporter                   &otel,
    int                             status_map_fd,
    int                             cgroup_bridge_map_fd,
    std::atomic<bool>              &stdout_network_drop_proof_logged,
    std::atomic<int>                &birth_worker_count,
    std::mutex                     &enforced_mu,
    std::unordered_map<std::uint64_t, KotaEnforcedHostRecord> &enforced_hosts)
    : resolver_(resolver)
    , profile_store_(profile_store)
    , cilium_(cilium)
    , vlogger_(vlogger)
    , otel_(otel)
    , status_map_fd_(status_map_fd)
    , cgroup_bridge_map_fd_(cgroup_bridge_map_fd)
    , stdout_network_drop_proof_logged_(stdout_network_drop_proof_logged)
    , birth_worker_count_(birth_worker_count)
    , enforced_mu_(enforced_mu)
    , enforced_hosts_(enforced_hosts)
{
}

void KotadRingDispatcher::maybe_log_violation_class_ring_event(
    const kota_event &ev) const
{
    if (!debug_ring_violations())
        return;
    switch (ev.event_type) {
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
        break;
    default:
        return;
    }
    struct in_addr da{};
    da.s_addr = ev.daddr_v4;
    char dbuf[INET_ADDRSTRLEN]{};
    if (inet_ntop(AF_INET, &da, dbuf, sizeof(dbuf)) == nullptr) {
        dbuf[0] = '?';
        dbuf[1] = '\0';
    }
    std::cerr << "[KOTA] ring(violation-class): event_type=" << ev.event_type
              << " cgroup_inode=" << ev.cgroup_inode << " daddr=" << dbuf << '\n';
}

void KotadRingDispatcher::try_log_stdout_network_drop_proof_once(
    const kota_event &ev)
{
    if (ev.event_type != KOTA_EVT_NETWORK_DROP)
        return;
    bool expected = false;
    if (stdout_network_drop_proof_logged_.compare_exchange_strong(
            expected, true, std::memory_order_relaxed)) {
        std::cout << "[KOTA] BPF NETWORK_DROP observed\n";
    }
}

void KotadRingDispatcher::maybe_learn_ioctl_bridge_from_event(const kota_event &ev)
{
    if (!debug_ioctl_bridge())
        return;
    if (ev.event_type != KOTA_EVT_IOCTL_AUDIT || ev.verdict_reason != 40)
        return;
    if (status_map_fd_ < 0 || cgroup_bridge_map_fd_ < 0 || ev.cgroup_inode == 0 || ev.pid == 0)
    {
        std::cerr << "[KOTA] IOCTL bridge skip: invalid preconditions "
                  << "(status_fd=" << status_map_fd_
                  << " bridge_fd=" << cgroup_bridge_map_fd_
                  << " cgid=" << ev.cgroup_inode
                  << " pid=" << ev.pid << ")\n";
        return;
    }

    const std::string proc_cgroup = "/proc/" + std::to_string(ev.pid) + "/cgroup";
    std::ifstream in(proc_cgroup);
    if (!in.is_open()) {
        std::cerr << "[KOTA] IOCTL bridge miss: cannot open " << proc_cgroup << '\n';
        return;
    }

    std::string line;
    std::string rel;
    while (std::getline(in, line)) {
        const auto pos = line.find("::");
        if (pos == std::string::npos)
            continue;
        rel = line.substr(pos + 2);
        break;
    }
    if (rel.empty()) {
        std::cerr << "[KOTA] IOCTL bridge miss: cgroup relpath missing for pid="
                  << ev.pid << '\n';
        return;
    }
    if (!rel.empty() && rel[0] == '/')
        rel.erase(0, 1);
    const std::filesystem::path cgroup_path = std::filesystem::path("/sys/fs/cgroup") / rel;

    bool had_stat_hit = false;
    for (auto p = cgroup_path; !p.empty() && p != p.root_path(); p = p.parent_path()) {
        struct stat st{};
        if (::stat(p.c_str(), &st) != 0)
            continue;
        had_stat_hit = true;
        const __u64 ino = static_cast<__u64>(st.st_ino);
        if (!ino)
            continue;
        struct kota_status_map_value sv{};
        if (bpf_map_lookup_elem(status_map_fd_, &ino, &sv) != 0)
            continue;
        if (sv.profile_id == 0)
            continue;

        const __u64 key = ev.cgroup_inode;
        const __u64 val = ino;
        if (bpf_map_update_elem(cgroup_bridge_map_fd_, &key, &val, BPF_ANY) == 0) {
            std::cout << "[KOTA] IOCTL bridge learned helper_cgid=" << key
                      << " -> canonical_inode=" << val
                      << " profile_id=" << sv.profile_id << '\n';
        } else {
            std::cerr << "[KOTA] IOCTL bridge miss: map update failed helper_cgid="
                      << key << " canonical_inode=" << val << '\n';
        }
        return;
    }

    if (!had_stat_hit) {
        std::cerr << "[KOTA] IOCTL bridge miss: cannot stat any cgroup path parent for pid="
                  << ev.pid << " path=" << cgroup_path << '\n';
    } else {
        std::cerr << "[KOTA] IOCTL bridge miss: no managed ancestor inode found in status map "
                  << "for pid=" << ev.pid << " helper_cgid=" << ev.cgroup_inode
                  << " path=" << cgroup_path << '\n';
    }
}

void KotadRingDispatcher::record_otel_metrics_for_ring_event(
    const kota_event &ev) const
{
    std::string pod_name;
    std::string namespace_name;
    {
        std::lock_guard<std::mutex> lock(enforced_mu_);
        if (const auto it = enforced_hosts_.find(ev.cgroup_inode);
            it != enforced_hosts_.end()) {
            pod_name = it->second.pod_name;
            namespace_name = it->second.namespace_name;
        }
    }

    switch (ev.event_type) {
    case KOTA_EVT_GPU_ACTIVE:
        otel_.record_gpu_stats(ev.cgroup_inode,
                               ev.ioctl_cmd ? uint64_t{ev.ioctl_cmd} : 1ull, 0);
        return;
    case KOTA_EVT_BIRTH:
        otel_.record_cgroup_event_processed("birth");
        return;
    case KOTA_EVT_DEATH:
        otel_.record_cgroup_event_processed("death");
        return;
    case KOTA_EVT_NETWORK_DROP:
        otel_.record_violation(ev.cgroup_inode, ev.event_type);
        otel_.record_packet_drop(pod_name, namespace_name, ev.dport, "egress");
        return;
    case KOTA_EVT_INGRESS_DROP:
        otel_.record_violation(ev.cgroup_inode, ev.event_type);
        otel_.record_packet_drop(pod_name, namespace_name, ev.dport, "ingress");
        return;
    case KOTA_EVT_NETWORK_AUDIT:
    case KOTA_EVT_QUARANTINE_DROP:
    case KOTA_EVT_FAILSAFE_FIRED:
    case KOTA_EVT_FAILSAFE_AUDIT:
    case KOTA_EVT_LICENSE_EXPIRED:
        otel_.record_violation(ev.cgroup_inode, ev.event_type);
        return;
    case KOTA_EVT_IOCTL_BLOCK:
        otel_.record_violation(ev.cgroup_inode, ev.event_type);
        otel_.record_lsm_veto_event(pod_name, namespace_name, "nvidia", "file_ioctl");
        return;
    case KOTA_EVT_MMAP_BLOCK:
        otel_.record_violation(ev.cgroup_inode, ev.event_type);
        otel_.record_lsm_veto_event(pod_name, namespace_name, "nvidia", "mmap");
        return;
    case KOTA_EVT_IOCTL_AUDIT:
    case KOTA_EVT_MMAP_AUDIT:
        otel_.record_violation(ev.cgroup_inode, ev.event_type);
        return;
    default:
        return;
    }
}

void KotadRingDispatcher::start_async_pod_resolve_after_birth(
    std::uint64_t cgroup_inode)
{
    std::thread(
        [this, cgroup_inode]() {
            BirthWorkerSlot slot{birth_worker_count_};

            auto t0 = std::chrono::high_resolution_clock::now();
            auto meta = resolver_.resolve(cgroup_inode);
            auto t1 = std::chrono::high_resolution_clock::now();
            const auto us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0)
                                .count();

            if (!meta) {
                if (meta.error().starts_with("skip:profile")) {
                    std::cout << "[KOTA] PodResolver: profile gate skip for inode="
                              << cgroup_inode << " (" << meta.error() << ")\n";
                } else if (!meta.error().starts_with("skip:")) {
                    std::cerr << "[KOTA] PodResolver: " << meta.error() << '\n';
                    otel_.record_identity_resolution_failure("resolve_failed");
                }
                return;
            }

            if (auto sid = cilium_.get_security_id(meta->pod_ip);
                sid.has_value() && *sid != 0u)
                meta->cilium_id = *sid;

            {
                const std::uint64_t leaf_ino =
                    meta->leaf_cgroup_inode ? meta->leaf_cgroup_inode
                                             : meta->cgroup_inode;
                std::cout << "[KOTA] Resolved Pod: " << meta->namespace_name << '/'
                          << meta->pod_name << " -> Inode: " << leaf_ino;
                if (!meta->host_veth_ifname.empty())
                    std::cout << " -> Iface: " << meta->host_veth_ifname;
                std::cout << " ip=" << meta->pod_ip
                          << " profile_id=" << meta->profile_id
                          << " trigger_inode=" << meta->cgroup_inode;
                if (meta->cilium_id)
                    std::cout << " cilium_id=" << meta->cilium_id;
                if (meta->profile_id != 0) {
                    if (auto yp = profile_store_.yaml_path_for(meta->profile_id); yp)
                        std::cout << " policy_yaml=" << yp->string();
                    else
                        std::cout << " policy_yaml=" << yp.error();
                } else {
                    std::cout << " policy=unmanaged";
                }
                std::cout << " (" << us << "µs pod-resolve)\n";
            }

            if (auto res = resolver_.enforce(*meta, meta->profile_id); !res) {
                std::cerr << "[KOTA] PodResolver: enforce: " << res.error() << '\n';
            } else {
                std::cout << "[KOTA] Identity enforced (ACTIVE) for "
                          << meta->namespace_name << '/' << meta->pod_name << '\n';

                otel_.record_policy_latency(meta->profile_id,
                                            static_cast<std::uint64_t>(us) * 1000ull,
                                            meta->pod_name,
                                            meta->namespace_name);

                {
                    std::lock_guard<std::mutex> lock(enforced_mu_);
                    enforced_hosts_[meta->cgroup_inode] = {
                        .pod_ip = meta->pod_ip,
                        .pod_name = meta->pod_name,
                        .namespace_name = meta->namespace_name,
                    };
                }
            }
        })
        .detach();
}

void KotadRingDispatcher::handle_pod_cgroup_death(const kota_event &ev)
{
    std::cout << "[KOTA] Pod died:  inode=" << ev.cgroup_inode << " seq=" << ev.seq_no
              << " ts=" << ev.timestamp_ns << '\n';

    std::string dead_ip;
    {
        std::lock_guard<std::mutex> lock(enforced_mu_);
        if (auto it = enforced_hosts_.find(ev.cgroup_inode);
            it != enforced_hosts_.end()) {
            dead_ip = std::move(it->second.pod_ip);
            enforced_hosts_.erase(it);
        }
    }
    if (!dead_ip.empty()) {
        if (auto r = resolver_.remove_ip_attribution(dead_ip, ev.cgroup_inode); !r)
            std::cerr << "[KOTA] remove_ip_attribution: " << r.error() << '\n';
    }
}

void KotadRingDispatcher::dispatch(const kota_event &ev)
{
    vlogger_.log_event(ev);
    maybe_learn_ioctl_bridge_from_event(ev);
    maybe_log_violation_class_ring_event(ev);
    try_log_stdout_network_drop_proof_once(ev);
    record_otel_metrics_for_ring_event(ev);

    if (ev.event_type == KOTA_EVT_BIRTH)
        start_async_pod_resolve_after_birth(ev.cgroup_inode);
    else if (ev.event_type == KOTA_EVT_DEATH)
        handle_pod_cgroup_death(ev);
}

} // namespace kota
