/*
 * KOTA Community Edition — TCX ingress “Scalpel” on host lxc* legs.
 * bpf_skb_cgroup_id(skb) for attribution (not bpf_get_current_cgroup_id()).
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "../maps/kota_maps.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define DNS_PORT      53
#define SSH_PORT      22
#define HTTPS_PORT    443
#define KUBELET_PORT  10250
#define MGMT_HTTP_PORT 8080
#define AI_HTTP_PORT   8000
#define AI_GRPC_PORT   5000

static __always_inline __u8 kota_lookup_policy_port_class(__u32 profile_id, __u16 port)
{
    if (!profile_id || !port)
        return KOTA_PORT_CLASS_UNKNOWN;
    struct kota_policy_port_key key = {};
    key.profile_id = profile_id;
    key.port = port;
    struct kota_policy_port_value *v =
        bpf_map_lookup_elem(&kota_policy_ports, &key);
    if (!v)
        return KOTA_PORT_CLASS_UNKNOWN;
    return v->port_class;
}

static __always_inline int kota_scalpel_enforce(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_UNSPEC;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_UNSPEC;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_UNSPEC;

    __u32 saddr = iph->saddr;
    __u32 daddr = iph->daddr;
    __u8 proto = iph->protocol;
    __u16 sport = 0, dport = 0;

    __u32 ip_hlen = (__u32)(iph->ihl & 0x0fu) << 2;
    if (ip_hlen < sizeof(*iph) || (void *)iph + ip_hlen > data_end)
        return TC_ACT_UNSPEC;

    void *l4 = (void *)iph + ip_hlen;
    if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) <= data_end) {
            sport = bpf_ntohs(udp->source);
            dport = bpf_ntohs(udp->dest);
        }
    } else if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) <= data_end) {
            sport = bpf_ntohs(tcp->source);
            dport = bpf_ntohs(tcp->dest);
        }
    }

    __u64 cgroup_id = bpf_skb_cgroup_id(skb);
    if (!cgroup_id) {
        kota_cgroup_ino *ip_ino = bpf_map_lookup_elem(&kota_ip_to_inode, &daddr);
        if (ip_ino)
            cgroup_id = *ip_ino;
    }
    if (!cgroup_id) {
        kota_cgroup_ino *ip_ino = bpf_map_lookup_elem(&kota_ip_to_inode, &saddr);
        if (ip_ino)
            cgroup_id = *ip_ino;
    }
    if (!cgroup_id)
        return TC_ACT_UNSPEC;

    struct kota_status_map_value *pod =
        bpf_map_lookup_elem(&kota_status_map, &cgroup_id);
    if (!pod && daddr) {
        kota_cgroup_ino *ip_ino = bpf_map_lookup_elem(&kota_ip_to_inode, &daddr);
        if (ip_ino) {
            cgroup_id = *ip_ino;
            pod = bpf_map_lookup_elem(&kota_status_map, &cgroup_id);
        }
    }
    if (!pod && saddr) {
        kota_cgroup_ino *ip_ino = bpf_map_lookup_elem(&kota_ip_to_inode, &saddr);
        if (ip_ino) {
            cgroup_id = *ip_ino;
            pod = bpf_map_lookup_elem(&kota_status_map, &cgroup_id);
        }
    }
    if (!pod)
        return TC_ACT_UNSPEC;

    /* Policy gate: only labeled/managed pods (profile_id != 0) are enforced. */
    if (pod->profile_id == 0)
        return TC_ACT_UNSPEC;

    if (pod->verdict != KOTA_VERDICT_VIOLATION)
        return TC_ACT_UNSPEC;

    const __u8 dclass = kota_lookup_policy_port_class(pod->profile_id, dport);
    const __u8 sclass = kota_lookup_policy_port_class(pod->profile_id, sport);
    if (dclass == KOTA_PORT_CLASS_MGMT || sclass == KOTA_PORT_CLASS_MGMT)
        return TC_ACT_UNSPEC;
    if (dclass == KOTA_PORT_CLASS_AI || sclass == KOTA_PORT_CLASS_AI)
        return TC_ACT_SHOT;

    if (proto == IPPROTO_UDP && (dport == DNS_PORT || sport == DNS_PORT))
        return TC_ACT_UNSPEC;
    if (proto == IPPROTO_TCP &&
        (dport == SSH_PORT || sport == SSH_PORT ||
         dport == HTTPS_PORT || sport == HTTPS_PORT ||
         dport == KUBELET_PORT || sport == KUBELET_PORT ||
         dport == MGMT_HTTP_PORT || sport == MGMT_HTTP_PORT))
        return TC_ACT_UNSPEC;

    if (proto == IPPROTO_TCP &&
        (dport == AI_HTTP_PORT || sport == AI_HTTP_PORT ||
         dport == AI_GRPC_PORT || sport == AI_GRPC_PORT))
        return TC_ACT_SHOT;

    (void)daddr;
    (void)sport;
    return TC_ACT_UNSPEC;
}

SEC("tcx/ingress")
int kota_scalpel_ingress(struct __sk_buff *skb)
{
    return kota_scalpel_enforce(skb);
}

SEC("tcx/egress")
int kota_scalpel_egress(struct __sk_buff *skb)
{
    return kota_scalpel_enforce(skb);
}
