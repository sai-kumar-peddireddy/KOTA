/*
 * KOTA CE — LSM file_ioctl "Veto" for GPU devices (docs/HLD.md).
 * bpf_get_current_cgroup_id() is valid in LSM context.
 *
 * S6.1 semantics (minimal deny subset):
 * - Scope to character-device ioctl calls.
 * - On VIOLATION, deny only NVIDIA RM ioctl namespace commands
 *   (_IOC_TYPE(cmd) == 'F', 0x46), which covers GPU control/dispatch paths.
 * - Leave non-RM ioctl namespaces untouched to reduce collateral behavior.
 */

#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/types.h>

#ifndef S_IFMT
#define S_IFMT 00170000
#endif
#ifndef S_IFCHR
#define S_IFCHR 0020000
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../maps/kota_maps.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define KOTA_IOC_NR_BITS       8
#define KOTA_IOC_TYPE_BITS     8
#define KOTA_IOC_TYPE_MASK     ((1U << KOTA_IOC_TYPE_BITS) - 1U)
#define KOTA_IOC_TYPE_SHIFT    KOTA_IOC_NR_BITS
#define KOTA_NVIDIA_IOC_TYPE_RM 0x46U /* 'F' */

struct kernfs_node___kota {
    __u64 id;
} __attribute__((preserve_access_index));

struct cgroup___kota {
    struct kernfs_node___kota *kn;
} __attribute__((preserve_access_index));

struct css_set___kota {
    struct cgroup___kota *dfl_cgrp;
} __attribute__((preserve_access_index));

struct task_struct___kota {
    struct css_set___kota *cgroups;
    void *nsproxy;
} __attribute__((preserve_access_index));

struct nsproxy___kota {
    void *net_ns;
} __attribute__((preserve_access_index));

struct net___kota {
    struct {
        __u32 inum;
    } ns;
} __attribute__((preserve_access_index));

static __always_inline __u64 kota_current_netns_inode(void)
{
    struct task_struct___kota *task =
        (struct task_struct___kota *)bpf_get_current_task_btf();
    if (!task)
        return 0;
    struct nsproxy___kota *nsp = BPF_CORE_READ(task, nsproxy);
    if (!nsp)
        return 0;
    struct net___kota *netns = (struct net___kota *)BPF_CORE_READ(nsp, net_ns);
    if (!netns)
        return 0;
    __u32 inum = 0;
    BPF_CORE_READ_INTO(&inum, netns, ns.inum);
    return (__u64)inum;
}

static __u64 kota_ioctl_event_seq_no = 0;

static __always_inline int kota_is_blocked_gpu_ioctl(__u32 cmd)
{
    __u32 type = (cmd >> KOTA_IOC_TYPE_SHIFT) & KOTA_IOC_TYPE_MASK;

    if (type == KOTA_NVIDIA_IOC_TYPE_RM)
        return 1;

    return 0;
}

static __always_inline __u8 kota_lookup_ioctl_action(__u32 profile_id, __u32 cmd)
{
    if (!profile_id || !cmd)
        return KOTA_IOCTL_ACTION_UNKNOWN;
    struct kota_policy_ioctl_key key = {};
    key.profile_id = profile_id;
    key.ioctl_cmd = cmd;
    struct kota_policy_ioctl_value *v =
        bpf_map_lookup_elem(&kota_policy_ioctl, &key);
    if (!v)
        return KOTA_IOCTL_ACTION_UNKNOWN;
    return v->action;
}

static __always_inline void
kota_emit_ioctl_event(__u32 event_type, __u64 cgroup_id, __u32 cmd,
                      __u32 profile_id, __u32 verdict_reason)
{
    struct kota_event *evt = bpf_ringbuf_reserve(&kota_events, sizeof(*evt), 0);
    if (!evt)
        return;
    __builtin_memset(evt, 0, sizeof(*evt));
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->event_type     = event_type;
    evt->cgroup_inode   = cgroup_id;
    evt->pid            = (__u32)(bpf_get_current_pid_tgid() >> 32);
    evt->ioctl_cmd      = cmd;
    evt->profile_id     = profile_id;
    evt->verdict_reason = verdict_reason;
    evt->seq_no         = __sync_fetch_and_add(&kota_ioctl_event_seq_no, 1);
    bpf_ringbuf_submit(evt, 0);
}

static __always_inline struct kota_status_map_value *
kota_lookup_status_with_ancestors(__u64 cgroup_id)
{
    __u64 netns_inode = kota_current_netns_inode();
    if (netns_inode) {
        struct kota_status_map_value *ns =
            bpf_map_lookup_elem(&kota_netns_status, &netns_inode);
        if (ns)
            return ns;
    }

    __u64 canonical = 0;
    if (cgroup_id) {
        __u64 *mapped = bpf_map_lookup_elem(&kota_cgroup_bridge, &cgroup_id);
        canonical = mapped ? *mapped : cgroup_id;
        struct kota_status_map_value *st =
            bpf_map_lookup_elem(&kota_status_map, &canonical);
        if (st)
            return st;
    }

    /*
     * Runtime exec paths can execute under child cgroups. Walk a bounded
     * ancestor window to find the managed pod/root entry in the same map.
     */
#pragma unroll
    for (__u32 level = 1; level <= 8; level++) {
        __u64 ancestor = bpf_get_current_ancestor_cgroup_id(level);
        if (!ancestor)
            break;
        __u64 *mapped = bpf_map_lookup_elem(&kota_cgroup_bridge, &ancestor);
        canonical = mapped ? *mapped : ancestor;
        struct kota_status_map_value *st =
            bpf_map_lookup_elem(&kota_status_map, &canonical);
        if (st)
            return st;
    }
    return (void *)0;
}

static __always_inline __u64 kota_current_cgroup_inode(void)
{
    struct task_struct___kota *task =
        (struct task_struct___kota *)bpf_get_current_task_btf();
    if (!task)
        return 0;
    struct css_set___kota *cgroups = BPF_CORE_READ(task, cgroups);
    if (!cgroups)
        return 0;
    struct cgroup___kota *dfl = BPF_CORE_READ(cgroups, dfl_cgrp);
    if (!dfl)
        return 0;
    return BPF_CORE_READ(dfl, kn, id);
}

SEC("lsm/file_ioctl")
int BPF_PROG(kota_file_ioctl, struct file *file, unsigned int cmd,
             unsigned long arg)
{
    if (!file)
        return 0;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!cgroup_id)
        return 0;

    if (!kota_is_blocked_gpu_ioctl(cmd))
        return 0;

    __u64 cgroup_inode = kota_current_cgroup_inode();
    struct kota_status_map_value *st = kota_lookup_status_with_ancestors(cgroup_id);
    if (!st && cgroup_inode && cgroup_inode != cgroup_id)
        st = kota_lookup_status_with_ancestors(cgroup_inode);
    if (!st) {
        /* no status for cgroup in helper-id or inode-id key spaces */
        kota_emit_ioctl_event(KOTA_EVT_IOCTL_AUDIT, cgroup_id, cmd, 0, 20);
        return 0;
    }

    /* Policy gate: only labeled/managed pods (profile_id != 0) are enforced. */
    if (st->profile_id == 0) {
        kota_emit_ioctl_event(KOTA_EVT_IOCTL_AUDIT, cgroup_id, cmd, 0, 21); /* unmanaged */
        return 0;
    }

    if (st->verdict != KOTA_VERDICT_VIOLATION) {
        kota_emit_ioctl_event(KOTA_EVT_IOCTL_AUDIT, cgroup_id, cmd,
                              st->profile_id, 22); /* managed but ACTIVE */
        return 0;
    }

    const __u8 action = kota_lookup_ioctl_action(st->profile_id, cmd);
    if (action != KOTA_IOCTL_ACTION_DENY) {
        kota_emit_ioctl_event(KOTA_EVT_IOCTL_AUDIT, cgroup_id, cmd,
                              st->profile_id, 25); /* VIOLATION but cmd not denied */
        return 0;
    }

    kota_emit_ioctl_event(KOTA_EVT_IOCTL_BLOCK, cgroup_id, cmd,
                          st->profile_id, 23); /* blocked by ioctl policy */

    (void)cmd;
    (void)arg;
    return -EACCES;
}
