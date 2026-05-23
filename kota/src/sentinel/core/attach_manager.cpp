#include "attach_manager.h"

#include "lifecycle.skel.h"
#include "scalpel.skel.h"
#include "veto.skel.h"
#include "ioctl_observer.skel.h"

#include <bpf/libbpf.h>
#include <linux/bpf.h>

#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <format>
#include <iostream>
#include <mutex>
#include <string>
#include <unordered_map>

#include <net/if.h>

namespace kota::attach {
namespace {

/* Optional boot-time TCX on one ifname (KOTA_TCX_IF); per-pod uses g_tcx_if_slots. */
struct bpf_link *g_boot_tcx_ingress_link = nullptr;
struct bpf_link *g_boot_tcx_egress_link  = nullptr;
struct scalpel  *g_scalpel = nullptr;
std::mutex       g_tcx_mu;

struct TcxSlot {
    struct bpf_link *ingress_link = nullptr;
    struct bpf_link *egress_link = nullptr;
    int              refs = 0;
};

std::unordered_map<std::string, TcxSlot> g_tcx_if_slots;
std::unordered_map<uint64_t, std::string> g_inode_to_ifname;

bool env_flag_enabled(const char *name, bool default_value)
{
    const char *e = std::getenv(name);
    if (!e || !*e)
        return default_value;
    return e[0] == '1' || e[0] == 't' || e[0] == 'T' || e[0] == 'y' ||
           e[0] == 'Y';
}

/* Successful TCX attach lines; errors stay on stderr. KOTA_QUIET_TCX_ATTACH=1
 * skips them to reduce stdout overhead on hot attach paths. */
static bool tcx_success_logs_enabled() noexcept
{
    return !env_flag_enabled("KOTA_QUIET_TCX_ATTACH", false);
}

bool bpf_lsm_supported_by_kernel()
{
    std::ifstream in{"/sys/kernel/security/lsm"};
    if (!in.is_open())
        return false;

    std::string line;
    std::getline(in, line);
    return line.find("bpf") != std::string::npos;
}

void release_ifname_locked(const std::string &ifname)
{
    auto it = g_tcx_if_slots.find(ifname);
    if (it == g_tcx_if_slots.end())
        return;

    --it->second.refs;
    if (it->second.refs <= 0) {
        if (it->second.ingress_link)
            bpf_link__destroy(it->second.ingress_link);
        if (it->second.egress_link)
            bpf_link__destroy(it->second.egress_link);
        g_tcx_if_slots.erase(it);
        std::cout << std::format("[KOTA] attach: TCX ingress+egress detached from `{}`\n",
                                 ifname);
    }
}

std::string effective_boot_tcx_ifname()
{
    if (const char *e = std::getenv("KOTA_TCX_IF"))
        return std::string{e};
    if (const char *e = std::getenv("KOTA_SMOKE_TCX_IF")) /* legacy alias */
        return std::string{e};
    return {};
}

} // namespace

void teardown_before_object_unload()
{
    {
        std::lock_guard<std::mutex> lock(g_tcx_mu);
        for (auto &[ifname, slot] : g_tcx_if_slots) {
            if (slot.ingress_link)
                bpf_link__destroy(slot.ingress_link);
            if (slot.egress_link)
                bpf_link__destroy(slot.egress_link);
            std::cout << std::format(
                "[KOTA] attach: TCX ingress+egress detached from `{}` (shutdown)\n",
                ifname);
        }
        g_tcx_if_slots.clear();
        g_inode_to_ifname.clear();
    }

    if (g_boot_tcx_ingress_link) {
        bpf_link__destroy(g_boot_tcx_ingress_link);
        g_boot_tcx_ingress_link = nullptr;
    }
    if (g_boot_tcx_egress_link) {
        bpf_link__destroy(g_boot_tcx_egress_link);
        g_boot_tcx_egress_link = nullptr;
    }

    g_scalpel = nullptr;
}

void attach_kernel_programs(struct lifecycle *lifecycle,
                            struct scalpel   *scalpel,
                            struct veto      *veto,
                            struct ioctl_observer *ioctl_observer)
{
    teardown_before_object_unload();

    g_scalpel = scalpel;

    if (lifecycle) {
        if (lifecycle__attach(lifecycle) != 0)
            std::cerr << std::format(
                "[KOTA] attach: cgroup tracepoints not attached: {}\n",
                std::strerror(errno));
        else
            std::cout << "[KOTA] attach: cgroup tracepoints (lifecycle)\n";
    }

    if (veto) {
        if (env_flag_enabled("KOTA_DISABLE_LSM", false)) {
            std::cout << "[KOTA] attach: LSM file_ioctl (veto) skipped (KOTA_DISABLE_LSM)\n";
        } else if (!bpf_lsm_supported_by_kernel()) {
            std::cerr
                << "[KOTA] attach: LSM file_ioctl (veto) skipped — kernel missing "
                   "BPF LSM support (CONFIG_BPF_LSM)\n";
        } else if (veto__attach(veto) != 0) {
            std::cerr << std::format(
                "[KOTA] attach: LSM file_ioctl (veto) not attached — {}\n",
                std::strerror(errno));
        } else {
            std::cout << "[KOTA] attach: LSM file_ioctl (veto)\n";
        }
    }

    if (ioctl_observer) {
        if (ioctl_observer__attach(ioctl_observer) != 0) {
            std::cerr << std::format(
                "[KOTA] attach: tracepoint sys_enter_ioctl (observer) not attached — {}\n",
                std::strerror(errno));
        } else {
            std::cout << "[KOTA] attach: tracepoint sys_enter_ioctl (observer)\n";
        }
    }

    /* Optional single-ifname boot TCX (lab); per-pod lxc* TCX is resolver-driven. */
    if (!scalpel)
        return;
    const std::string ifn = effective_boot_tcx_ifname();
    if (ifn.empty())
        return;

    const unsigned ifidx = if_nametoindex(ifn.c_str());
    if (ifidx == 0) {
        std::cerr << std::format(
            "[KOTA] attach: boot TCX skipped — interface `{}`: {}\n", ifn,
            std::strerror(errno));
        return;
    }

    struct bpf_tcx_opts tcx{};
    tcx.sz    = sizeof(tcx);
    tcx.flags = BPF_F_BEFORE;
    g_boot_tcx_ingress_link = bpf_program__attach_tcx(
        scalpel->progs.kota_scalpel_ingress, static_cast<int>(ifidx), &tcx);
    if (!g_boot_tcx_ingress_link)
        std::cerr << std::format(
            "[KOTA] attach: boot TCX ingress on `{}` failed: {}\n", ifn,
            std::strerror(errno));
    else {
        std::cout << std::format(
            "[KOTA] attach: boot TCX ingress (Scalpel) on `{}` (ifindex {})\n", ifn,
            ifidx);
        g_boot_tcx_egress_link = bpf_program__attach_tcx(
            scalpel->progs.kota_scalpel_egress, static_cast<int>(ifidx), &tcx);
        if (!g_boot_tcx_egress_link)
            std::cerr << std::format(
                "[KOTA] attach: boot TCX egress on `{}` failed: {}\n", ifn,
                std::strerror(errno));
        else
            std::cout << std::format(
                "[KOTA] attach: boot TCX egress (Scalpel) on `{}` (ifindex {})\n", ifn,
                ifidx);
    }
}

/* Scalpel TCX programs are loaded and verified once in BpfLoader::load(); this
 * path only creates bpf_link attachments to the resolved lxc* ifindex. */
extern "C" void kota_on_host_veth_resolved(uint64_t cgroup_inode,
                                           const char *ifname)
{
    if (cgroup_inode == 0 || ifname == nullptr || ifname[0] == '\0')
        return;

    if (!g_scalpel || g_scalpel->progs.kota_scalpel_ingress == nullptr)
        return;

    std::lock_guard<std::mutex> lock(g_tcx_mu);

    const std::string ifn{ifname};
    if (auto prev = g_inode_to_ifname.find(cgroup_inode);
        prev != g_inode_to_ifname.end() && prev->second != ifn) {
        std::cout << std::format(
            "[KOTA] attach: resolver iface update inode={} `{}` -> `{}`\n",
            cgroup_inode, prev->second, ifn);
        release_ifname_locked(prev->second);
        g_inode_to_ifname.erase(prev);
    } else if (prev != g_inode_to_ifname.end()) {
        return;
    }

    auto &slot = g_tcx_if_slots[ifn];
    if (slot.refs == 0) {
        const unsigned ifidx = if_nametoindex(ifn.c_str());
        if (ifidx == 0) {
            g_tcx_if_slots.erase(ifn);
            std::cerr << std::format(
                "[KOTA] attach: TCX callback skipped — interface `{}`: {}\n",
                ifn, std::strerror(errno));
            return;
        }

        struct bpf_tcx_opts tcx{};
        tcx.sz    = sizeof(tcx);
        tcx.flags = BPF_F_BEFORE;
        slot.ingress_link = bpf_program__attach_tcx(
            g_scalpel->progs.kota_scalpel_ingress, static_cast<int>(ifidx), &tcx);
        if (!slot.ingress_link) {
            g_tcx_if_slots.erase(ifn);
            std::cerr << std::format(
                "[KOTA] attach: TCX callback ingress attach failed on `{}`: {}\n", ifn,
                std::strerror(errno));
            return;
        }

        slot.egress_link = bpf_program__attach_tcx(
            g_scalpel->progs.kota_scalpel_egress, static_cast<int>(ifidx), &tcx);
        if (!slot.egress_link) {
            bpf_link__destroy(slot.ingress_link);
            g_tcx_if_slots.erase(ifn);
            std::cerr << std::format(
                "[KOTA] attach: TCX callback egress attach failed on `{}`: {}\n",
                ifn, std::strerror(errno));
            return;
        }
        if (tcx_success_logs_enabled()) {
            std::cout << std::format(
                "[KOTA] attach: resolver->TCX ingress+egress inode={} target=`{}` ifindex={}\n",
                cgroup_inode, ifn, ifidx);
        }
    }

    ++slot.refs;
    g_inode_to_ifname[cgroup_inode] = ifn;
    if (tcx_success_logs_enabled()) {
        std::cout << std::format(
            "[KOTA] attach: resolver->TCX inode={} target=`{}` refs={}\n",
            cgroup_inode, ifn, slot.refs);
    }
}

extern "C" void kota_on_cgroup_removed(uint64_t cgroup_inode)
{
    if (cgroup_inode == 0)
        return;

    std::lock_guard<std::mutex> lock(g_tcx_mu);
    auto it = g_inode_to_ifname.find(cgroup_inode);
    if (it == g_inode_to_ifname.end())
        return;
    release_ifname_locked(it->second);
    g_inode_to_ifname.erase(it);
}

} // namespace kota::attach
