#ifndef KOTA_MAPS_H
#define KOTA_MAPS_H

/*
 * BPF maps for KOTA Community Edition — StatusMap, IP_to_Inode, events ring buffer.
 * max_entries are compile-time defaults; Sentinel may override before load.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/shared/kota_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, KOTA_DEFAULT_STATUS_MAP_ENTRIES);
    __type(key, __u64);
    __type(value, struct kota_status_map_value);
} kota_status_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, KOTA_DEFAULT_IP_TO_INODE_ENTRIES);
    __type(key, kota_ipv4_be);
    __type(value, kota_cgroup_ino);
} kota_ip_to_inode SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct kota_policy_port_key);
    __type(value, struct kota_policy_port_value);
} kota_policy_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct kota_policy_ioctl_key);
    __type(value, struct kota_policy_ioctl_value);
} kota_policy_ioctl SEC(".maps");

/* Bridge helper cgroup ID space -> canonical pod cgroup inode key space. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, KOTA_DEFAULT_CGROUP_BRIDGE_ENTRIES);
    __type(key, __u64);
    __type(value, __u64);
} kota_cgroup_bridge SEC(".maps");

/* Netns cookie -> pod status for stable ioctl attribution across exec/slices. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, KOTA_DEFAULT_NETNS_STATUS_ENTRIES);
    __type(key, __u64);
    __type(value, struct kota_status_map_value);
} kota_netns_status SEC(".maps");

/* Ring buffer to Sentinel — must match kota_bpf_user_abi.h kota_event (96 bytes, align 8). */
#define KOTA_EVT_BIRTH 1u
#define KOTA_EVT_DEATH 2u
#define KOTA_EVT_IOCTL_BLOCK 6u
#define KOTA_EVT_IOCTL_AUDIT 7u

struct kota_event {
	__u64 timestamp_ns;
	__u64 cgroup_inode;
	__u64 seq_no;
	__u32 event_type;
	__u32 pid;
	__u32 saddr_v4;
	__u32 daddr_v4;
	__u32 ioctl_cmd;
	__u32 profile_id;
	__u32 verdict_reason;
	__u16 sport;
	__u16 dport;
	__u8  protocol;
	__u8  _pad[7];
	__u8  _reserved[32];
} __attribute__((aligned(8)));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 * 1024 * 1024);
} kota_events SEC(".maps");

#endif /* KOTA_MAPS_H */
