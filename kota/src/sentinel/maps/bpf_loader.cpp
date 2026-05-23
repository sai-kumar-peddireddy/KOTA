/*
 * S1.1 BpfLoader — CE lifecycle + scalpel + veto skeletons; shared StatusMap /
 * IP_to_Inode; pins under cfg.bpffs_path using names from kota_common.h.
 *
 * Bring-up (root + bpffs): after `kotad` loads, inspect pinned state with e.g.
 *   Maps: bpftool map list | grep kota_
 *   Progs: bpftool prog list | grep -E 'kota_|cgroup|lsm|tcx'
 * Optional boot TCX: KOTA_TCX_IF=lo (legacy KOTA_SMOKE_TCX_IF); attach policy
 * is attach_manager.cpp + main --help text.
 */

#include "bpf_loader.h"

#include "../core/attach_manager.h"
#include "kota_bpf_user_abi.h"
#include "../../../include/shared/kota_common.h"

// clang-format off
#include "lifecycle.skel.h"
#include "ioctl_observer.skel.h"
#include "scalpel.skel.h"
#include "veto.skel.h"
// clang-format on

#include <bpf/libbpf.h>

#include <cerrno>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <iostream>
#include <unistd.h>

#include <net/if.h>

namespace kota {

namespace {

struct lifecycle *g_lifecycle = nullptr;
struct scalpel   *g_scalpel   = nullptr;
struct veto      *g_veto      = nullptr;
struct ioctl_observer *g_ioctl_observer = nullptr;

bool ioctl_observer_enabled()
{
    const char *e = std::getenv("KOTA_ENABLE_IOCTL_OBSERVER");
    return e && (e[0] == '1' || e[0] == 't' || e[0] == 'T' || e[0] == 'y' ||
                 e[0] == 'Y');
}

int libbpf_log_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    std::fputs("[KOTA] libbpf: ", stderr);
    return std::vfprintf(stderr, fmt, args);
}

std::expected<void, std::string> pin_map(struct bpf_map *m, const std::string &path)
{
    ::unlink(path.c_str());
    if (bpf_map__pin(m, path.c_str()) != 0)
        return std::unexpected(
            std::format("bpf_map__pin({}) → {}", path, std::strerror(errno)));
    return {};
}

void reuse_maps_scalpel(struct scalpel *s, struct lifecycle *p)
{
    bpf_map__reuse_fd(s->maps.kota_status_map,
                      bpf_map__fd(p->maps.kota_status_map));
    bpf_map__reuse_fd(s->maps.kota_ip_to_inode,
                      bpf_map__fd(p->maps.kota_ip_to_inode));
    bpf_map__reuse_fd(s->maps.kota_policy_ports,
                      bpf_map__fd(p->maps.kota_policy_ports));
    bpf_map__reuse_fd(s->maps.kota_policy_ioctl,
                      bpf_map__fd(p->maps.kota_policy_ioctl));
    bpf_map__reuse_fd(s->maps.kota_cgroup_bridge,
                      bpf_map__fd(p->maps.kota_cgroup_bridge));
    bpf_map__reuse_fd(s->maps.kota_netns_status,
                      bpf_map__fd(p->maps.kota_netns_status));
}

void reuse_maps_veto(struct veto *v, struct lifecycle *p)
{
    bpf_map__reuse_fd(v->maps.kota_status_map,
                      bpf_map__fd(p->maps.kota_status_map));
    bpf_map__reuse_fd(v->maps.kota_ip_to_inode,
                      bpf_map__fd(p->maps.kota_ip_to_inode));
    bpf_map__reuse_fd(v->maps.kota_policy_ports,
                      bpf_map__fd(p->maps.kota_policy_ports));
    bpf_map__reuse_fd(v->maps.kota_policy_ioctl,
                      bpf_map__fd(p->maps.kota_policy_ioctl));
    bpf_map__reuse_fd(v->maps.kota_cgroup_bridge,
                      bpf_map__fd(p->maps.kota_cgroup_bridge));
    bpf_map__reuse_fd(v->maps.kota_netns_status,
                      bpf_map__fd(p->maps.kota_netns_status));
}

void reuse_maps_ioctl_observer(struct ioctl_observer *o, struct lifecycle *p)
{
    bpf_map__reuse_fd(o->maps.kota_status_map,
                      bpf_map__fd(p->maps.kota_status_map));
    bpf_map__reuse_fd(o->maps.kota_cgroup_bridge,
                      bpf_map__fd(p->maps.kota_cgroup_bridge));
    bpf_map__reuse_fd(o->maps.kota_netns_status,
                      bpf_map__fd(p->maps.kota_netns_status));
    bpf_map__reuse_fd(o->maps.kota_events,
                      bpf_map__fd(p->maps.kota_events));
}

void destroy_skels()
{
    if (g_ioctl_observer) {
        ioctl_observer__destroy(g_ioctl_observer);
        g_ioctl_observer = nullptr;
    }
    if (g_veto) {
        veto__destroy(g_veto);
        g_veto = nullptr;
    }
    if (g_scalpel) {
        scalpel__destroy(g_scalpel);
        g_scalpel = nullptr;
    }
    if (g_lifecycle) {
        lifecycle__destroy(g_lifecycle);
        g_lifecycle = nullptr;
    }
}

} // namespace

BpfLoader::BpfLoader(BpfConfig cfg) : cfg_(std::move(cfg)) {}

BpfLoader::~BpfLoader() { unload(); }

std::expected<void, std::string> BpfLoader::load()
{
    if (loaded_)
        return {};

    libbpf_set_print(libbpf_log_fn);

    std::error_code ec;
    std::filesystem::create_directories(cfg_.bpffs_path, ec);
    if (ec) {
        return std::unexpected(
            std::format("create_directories({}) → {}", cfg_.bpffs_path,
                        ec.message()));
    }

    g_lifecycle = lifecycle__open();
    if (!g_lifecycle)
        return std::unexpected(std::format("lifecycle__open → {}",
                                           std::strerror(errno)));

    bpf_map__set_max_entries(g_lifecycle->maps.kota_status_map,
                             cfg_.status_map_size);
    bpf_map__set_max_entries(g_lifecycle->maps.kota_ip_to_inode,
                             cfg_.ip_to_inode_size);
    bpf_map__set_max_entries(g_lifecycle->maps.kota_policy_ports,
                             8192);
    bpf_map__set_max_entries(g_lifecycle->maps.kota_policy_ioctl,
                             8192);
    bpf_map__set_max_entries(g_lifecycle->maps.kota_cgroup_bridge,
                             KOTA_DEFAULT_CGROUP_BRIDGE_ENTRIES);
    bpf_map__set_max_entries(g_lifecycle->maps.kota_netns_status,
                             KOTA_DEFAULT_NETNS_STATUS_ENTRIES);
    bpf_map__set_max_entries(g_lifecycle->maps.kota_events,
                             cfg_.ringbuf_size_bytes);

    if (lifecycle__load(g_lifecycle) != 0) {
        const int e = errno;
        destroy_skels();
        return std::unexpected(
            std::format("lifecycle__load → {}", std::strerror(e)));
    }
    std::cout << "[KOTA] BpfLoader: lifecycle loaded\n";

    g_scalpel = scalpel__open();
    if (!g_scalpel) {
        const int e = errno;
        destroy_skels();
        return std::unexpected(std::format("scalpel__open → {}",
                                           std::strerror(e)));
    }
    reuse_maps_scalpel(g_scalpel, g_lifecycle);
    if (scalpel__load(g_scalpel) != 0) {
        const int e = errno;
        destroy_skels();
        return std::unexpected(
            std::format("scalpel__load → {}", std::strerror(e)));
    }
    std::cout << "[KOTA] BpfLoader: scalpel loaded (shared maps)\n";

    g_veto = veto__open();
    if (!g_veto) {
        const int e = errno;
        destroy_skels();
        return std::unexpected(
            std::format("veto__open → {}", std::strerror(e)));
    }
    reuse_maps_veto(g_veto, g_lifecycle);
    if (veto__load(g_veto) != 0) {
        const int e = errno;
        destroy_skels();
        return std::unexpected(std::format("veto__load → {}",
                                           std::strerror(e)));
    }
    std::cout << "[KOTA] BpfLoader: veto loaded (shared maps)\n";

    if (ioctl_observer_enabled()) {
        g_ioctl_observer = ioctl_observer__open();
        if (!g_ioctl_observer) {
            const int e = errno;
            destroy_skels();
            return std::unexpected(
                std::format("ioctl_observer__open → {}", std::strerror(e)));
        }
        reuse_maps_ioctl_observer(g_ioctl_observer, g_lifecycle);
        if (ioctl_observer__load(g_ioctl_observer) != 0) {
            const int e = errno;
            destroy_skels();
            return std::unexpected(std::format("ioctl_observer__load → {}",
                                               std::strerror(e)));
        }
        std::cout << "[KOTA] BpfLoader: ioctl_observer loaded (shared maps)\n";
    } else {
        std::cout << "[KOTA] BpfLoader: ioctl_observer disabled (set KOTA_ENABLE_IOCTL_OBSERVER=1 to enable)\n";
    }

    const std::string &base = cfg_.bpffs_path;
    if (auto r = pin_map(g_lifecycle->maps.kota_status_map,
                         base + "/" + KOTA_MAP_STATUS_MAP);
        !r) {
        destroy_skels();
        return r;
    }
    map_fds_[KOTA_MAP_STATUS_MAP] =
        bpf_map__fd(g_lifecycle->maps.kota_status_map);

    if (auto r = pin_map(g_lifecycle->maps.kota_ip_to_inode,
                         base + "/" + KOTA_MAP_IP_TO_INODE);
        !r) {
        destroy_skels();
        return r;
    }
    map_fds_[KOTA_MAP_IP_TO_INODE] =
        bpf_map__fd(g_lifecycle->maps.kota_ip_to_inode);

    if (auto r = pin_map(g_lifecycle->maps.kota_policy_ports,
                         base + "/" + KOTA_MAP_POLICY_PORTS);
        !r) {
        destroy_skels();
        return r;
    }
    map_fds_[KOTA_MAP_POLICY_PORTS] =
        bpf_map__fd(g_lifecycle->maps.kota_policy_ports);

    if (auto r = pin_map(g_lifecycle->maps.kota_policy_ioctl,
                         base + "/" + KOTA_MAP_POLICY_IOCTL);
        !r) {
        destroy_skels();
        return r;
    }
    map_fds_[KOTA_MAP_POLICY_IOCTL] =
        bpf_map__fd(g_lifecycle->maps.kota_policy_ioctl);

    if (auto r = pin_map(g_lifecycle->maps.kota_cgroup_bridge,
                         base + "/" + KOTA_MAP_CGROUP_BRIDGE);
        !r) {
        destroy_skels();
        return r;
    }
    map_fds_[KOTA_MAP_CGROUP_BRIDGE] =
        bpf_map__fd(g_lifecycle->maps.kota_cgroup_bridge);

    if (auto r = pin_map(g_lifecycle->maps.kota_netns_status,
                         base + "/" + KOTA_MAP_NETNS_STATUS);
        !r) {
        destroy_skels();
        return r;
    }
    map_fds_[KOTA_MAP_NETNS_STATUS] =
        bpf_map__fd(g_lifecycle->maps.kota_netns_status);

    if (auto r = pin_map(g_lifecycle->maps.kota_events,
                         base + "/" + std::string(KOTA_MAP_EVENTS));
        !r) {
        destroy_skels();
        return r;
    }
    map_fds_[KOTA_MAP_EVENTS] = bpf_map__fd(g_lifecycle->maps.kota_events);

    std::cout << std::format("[KOTA] BpfLoader: pinned {}, {}, {}, {}, {}, {}, {} under {}\n",
                             KOTA_MAP_STATUS_MAP, KOTA_MAP_IP_TO_INODE,
                             KOTA_MAP_POLICY_PORTS, KOTA_MAP_POLICY_IOCTL,
                             KOTA_MAP_CGROUP_BRIDGE,
                             KOTA_MAP_NETNS_STATUS, KOTA_MAP_EVENTS, base);

    kota::attach::attach_kernel_programs(g_lifecycle, g_scalpel, g_veto,
                                         g_ioctl_observer);

    loaded_ = true;
    return {};
}

void BpfLoader::unload()
{
    kota::attach::teardown_before_object_unload();

    if (!loaded_) {
        destroy_skels();
        map_fds_.clear();
        return;
    }

    /* Pinned maps intentionally remain (docs/LLD.md); links detach via destroy. */
    destroy_skels();
    map_fds_.clear();
    loaded_ = false;
    std::cout << std::format(
        "[KOTA] BpfLoader: unloaded (pins retained under {})\n",
        cfg_.bpffs_path);
}

int BpfLoader::map_fd(std::string_view map_name) const
{
    auto it = map_fds_.find(std::string{map_name});
    if (it == map_fds_.end())
        return -1;
    return it->second;
}

struct bpf_link *BpfLoader::attach_ingress_tcx(const char *ifname) const
{
    if (!loaded_ || !ifname || !g_scalpel)
        return nullptr;
    const unsigned ifidx = if_nametoindex(ifname);
    if (ifidx == 0)
        return nullptr;
    struct bpf_tcx_opts tcx{};
    tcx.sz    = sizeof(tcx);
    tcx.flags = BPF_F_BEFORE;
    return bpf_program__attach_tcx(
        g_scalpel->progs.kota_scalpel_ingress, static_cast<int>(ifidx), &tcx);
}

} // namespace kota
