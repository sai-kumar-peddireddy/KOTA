#pragma once

/*
 * Userspace definitions that must stay binary-compatible with BPF programs and
 * `src/bpf/maps/kota_maps.h`: pinned map names, ring-buffer `kota_event` layout,
 * and event type IDs. This is the Sentinel (kotad) ↔ kernel BPF ABI .
 */

#include <linux/types.h>

#include "../../../include/shared/kota_common.h"

#define KOTA_MAP_PROFILE_MAP   "kota_profile_map"
#define KOTA_MAP_TELEMETRY     "kota_telemetry"
#define KOTA_MAP_EVENTS        "kota_events"
#define KOTA_MAP_POLICY_PORTS  "kota_policy_ports"
#define KOTA_MAP_POLICY_IOCTL  "kota_policy_ioctl"
#define KOTA_MAP_CGROUP_BRIDGE "kota_cgroup_bridge"
#define KOTA_MAP_NETNS_STATUS  "kota_netns_status"
#define KOTA_MAP_LICENSE       "kota_license"
#define KOTA_MAP_HEARTBEAT     "kota_heartbeat"
#define KOTA_MAP_KILL_SWITCH   "kota_kill_switch"
#define KOTA_MAP_METADATA      "kota_metadata"

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

enum kota_event_type {
    KOTA_EVT_BIRTH            = 1,
    KOTA_EVT_DEATH            = 2,
    KOTA_EVT_GPU_ACTIVE       = 3,
    KOTA_EVT_NETWORK_DROP     = 4,
    KOTA_EVT_NETWORK_AUDIT    = 5,
    KOTA_EVT_IOCTL_BLOCK      = 6,
    KOTA_EVT_IOCTL_AUDIT      = 7,
    KOTA_EVT_LICENSE_EXPIRED  = 8,
    KOTA_EVT_FAILSAFE_FIRED   = 9,
    KOTA_EVT_MMAP_BLOCK       = 10,
    KOTA_EVT_MMAP_AUDIT       = 11,
    KOTA_EVT_INGRESS_DROP     = 12,
    KOTA_EVT_QUARANTINE_DROP  = 13,
    KOTA_EVT_FAILSAFE_AUDIT   = 14,
};
