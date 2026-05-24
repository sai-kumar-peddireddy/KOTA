/*
 * KOTA Community Edition — cgroup lifecycle (tp_btf/cgroup_mkdir | cgroup_rmdir).
 * CO-RE inode via cgroup kn->id; ringbuf BIRTH/DEATH to Sentinel.
 * Enforcement map ownership is user-space only (resolver/enforce path).
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../maps/kota_maps.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct kernfs_node___kota {
	__u64 id;
} __attribute__((preserve_access_index));

struct cgroup___kota {
	struct kernfs_node___kota *kn;
} __attribute__((preserve_access_index));

static __u64 event_seq_no = 0;

static __always_inline void emit_event(__u64 now, __u64 cgroup_inode, __u32 type)
{
	struct kota_event *evt = bpf_ringbuf_reserve(&kota_events, sizeof(*evt), 0);
	if (!evt)
		return;
	__builtin_memset(evt, 0, sizeof(*evt));
	evt->timestamp_ns = now;
	evt->cgroup_inode = cgroup_inode;
	evt->event_type = type;
	evt->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	evt->seq_no = __sync_fetch_and_add(&event_seq_no, 1);
	bpf_ringbuf_submit(evt, 0);
}

SEC("tp_btf/cgroup_mkdir")
int BPF_PROG(handle_cgroup_mkdir, struct cgroup *cgrp, const char *path)
{
	(void)path;
	__u64 cgroup_inode = BPF_CORE_READ((struct cgroup___kota *)cgrp, kn, id);
	if (!cgroup_inode)
		return 0;

	__u64 now = bpf_ktime_get_ns();
	emit_event(now, cgroup_inode, KOTA_EVT_BIRTH);
	return 0;
}

SEC("tp_btf/cgroup_rmdir")
int BPF_PROG(handle_cgroup_rmdir, struct cgroup *cgrp, const char *path)
{
	(void)path;
	__u64 cgroup_inode = BPF_CORE_READ((struct cgroup___kota *)cgrp, kn, id);
	if (!cgroup_inode)
		return 0;

	__u64 now = bpf_ktime_get_ns();
	emit_event(now, cgroup_inode, KOTA_EVT_DEATH);
	return 0;
}
