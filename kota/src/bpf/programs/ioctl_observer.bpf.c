/*
 * KOTA CE — ioctl observer (read-only diagnostics).
 * Captures RM ioctl call attribution to managed pod status via cgroup map lookup.
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "../maps/kota_maps.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define KOTA_IOC_NR_BITS        8
#define KOTA_IOC_TYPE_BITS      8
#define KOTA_IOC_TYPE_MASK      ((1U << KOTA_IOC_TYPE_BITS) - 1U)
#define KOTA_IOC_TYPE_SHIFT     KOTA_IOC_NR_BITS
#define KOTA_NVIDIA_IOC_TYPE_RM 0x46U /* 'F' */

/* Minimal tracepoint context for sys_enter: id + args[6]. */
struct trace_event_raw_sys_enter___kota {
    __u64 _pad;
    long id;
    unsigned long args[6];
};

struct task_struct___kota {
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

static __always_inline __u64 current_netns_inode(void)
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

static __u64 kota_ioctl_obs_seq = 0;

static __always_inline int is_rm_ioctl(__u32 cmd)
{
    __u32 type = (cmd >> KOTA_IOC_TYPE_SHIFT) & KOTA_IOC_TYPE_MASK;
    return type == KOTA_NVIDIA_IOC_TYPE_RM;
}

static __always_inline struct kota_status_map_value *
lookup_status_with_ancestors(__u64 cgroup_id)
{
    __u64 netns_inode = current_netns_inode();
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
#pragma unroll
    for (__u32 level = 1; level <= 8; level++) {
        __u64 anc = bpf_get_current_ancestor_cgroup_id(level);
        if (!anc)
            break;
        __u64 *mapped = bpf_map_lookup_elem(&kota_cgroup_bridge, &anc);
        canonical = mapped ? *mapped : anc;
        struct kota_status_map_value *st =
            bpf_map_lookup_elem(&kota_status_map, &canonical);
        if (st)
            return st;
    }
    return (void *)0;
}

static __always_inline void emit_obs(__u64 cgroup_id, __u32 cmd,
                                     __u32 profile_id, __u32 reason)
{
    struct kota_event *evt = bpf_ringbuf_reserve(&kota_events, sizeof(*evt), 0);
    if (!evt)
        return;
    __builtin_memset(evt, 0, sizeof(*evt));
    evt->timestamp_ns   = bpf_ktime_get_ns();
    evt->cgroup_inode   = cgroup_id;
    evt->seq_no         = __sync_fetch_and_add(&kota_ioctl_obs_seq, 1);
    evt->event_type     = KOTA_EVT_IOCTL_AUDIT;
    evt->pid            = (__u32)(bpf_get_current_pid_tgid() >> 32);
    evt->ioctl_cmd      = cmd;
    evt->profile_id     = profile_id;
    evt->verdict_reason = reason;
    bpf_ringbuf_submit(evt, 0);
}

SEC("tracepoint/syscalls/sys_enter_ioctl")
int kota_ioctl_observer(struct trace_event_raw_sys_enter___kota *ctx)
{
    if (!ctx)
        return 0;

    __u32 cmd = (__u32)ctx->args[1];
    if (!is_rm_ioctl(cmd))
        return 0;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct kota_status_map_value *st = lookup_status_with_ancestors(cgroup_id);
    if (!st) {
        emit_obs(cgroup_id, cmd, 0, 40); /* observer: no status */
        return 0;
    }
    if (st->profile_id == 0) {
        emit_obs(cgroup_id, cmd, 0, 41); /* observer: unmanaged */
        return 0;
    }
    if (st->verdict == KOTA_VERDICT_VIOLATION) {
        emit_obs(cgroup_id, cmd, st->profile_id, 43); /* observer: managed+violation */
        return 0;
    }
    emit_obs(cgroup_id, cmd, st->profile_id, 42); /* observer: managed+active */
    return 0;
}

