#ifndef KOTA_COMMON_H
#define KOTA_COMMON_H

#include <linux/types.h>


#define KOTA_SCHEMA_VERSION 1u


#define KOTA_MAP_STATUS_MAP    "kota_status_map"
#define KOTA_MAP_IP_TO_INODE   "kota_ip_to_inode"
#define KOTA_MAP_POLICY_PORTS  "kota_policy_ports"
#define KOTA_MAP_POLICY_IOCTL  "kota_policy_ioctl"
#define KOTA_MAP_CGROUP_BRIDGE "kota_cgroup_bridge"
#define KOTA_MAP_NETNS_STATUS  "kota_netns_status"

#define KOTA_DEFAULT_STATUS_MAP_ENTRIES    16384u
#define KOTA_DEFAULT_IP_TO_INODE_ENTRIES 16384u
#define KOTA_DEFAULT_CGROUP_BRIDGE_ENTRIES 65536u
#define KOTA_DEFAULT_NETNS_STATUS_ENTRIES 65536u

enum kota_verdict {
    KOTA_VERDICT_ACTIVE = 0,
    KOTA_VERDICT_VIOLATION = 1,
};

struct kota_status_map_value {
    __u32 schema_version;
    __u32 verdict; /* enum kota_verdict */
    
    __u32 profile_id;
    __u32 cilium_id;
    __u64 birth_ns; /* cgroup_mkdir time; inode reuse guard in lifecycle BPF */
    __u64 updated_monotonic_ns;
    __u8  _reserved[24];
} __attribute__((aligned(8)));

enum kota_policy_port_class {
    KOTA_PORT_CLASS_UNKNOWN = 0,
    KOTA_PORT_CLASS_MGMT    = 1,
    KOTA_PORT_CLASS_AI      = 2,
};

struct kota_policy_port_key {
    __u32 profile_id;
    __u16 port;
    __u16 _reserved;
} __attribute__((aligned(8)));

enum kota_policy_ioctl_action {
    KOTA_IOCTL_ACTION_UNKNOWN = 0,
    KOTA_IOCTL_ACTION_ALLOW   = 1,
    KOTA_IOCTL_ACTION_DENY    = 2,
};

struct kota_policy_ioctl_key {
    __u32 profile_id;
    __u32 ioctl_cmd;
} __attribute__((aligned(8)));

struct kota_policy_ioctl_value {
    __u8 action; /* enum kota_policy_ioctl_action */
    __u8 _reserved[7];
} __attribute__((aligned(8)));

struct kota_policy_port_value {
    __u8  port_class; /* enum kota_policy_port_class */
    __u8  _reserved[7];
} __attribute__((aligned(8)));

typedef __u32 kota_ipv4_be;
typedef __u64 kota_cgroup_ino;

#endif /* KOTA_COMMON_H */
