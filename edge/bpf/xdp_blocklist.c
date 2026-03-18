#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_vlan.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1048576);
    __type(key, __u32);
    __type(value, __u8);
} blocked_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1048576);
    __type(key, struct in6_addr);
    __type(value, __u8);
} blocked_ipv6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} qidconf_map SEC(".maps");

static __always_inline void inc_counter(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&counters, &idx);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

SEC("xdp")
int xdp_blocklist_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        inc_counter(1);
        return XDP_PASS;
    }

    __u16 h_proto = eth->h_proto;
    void *pos = (void *)(eth + 1);
    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vh = pos;
        if ((void *)(vh + 1) > data_end) {
            inc_counter(1);
            return XDP_PASS;
        }
        h_proto = vh->h_vlan_encapsulated_proto;
        pos = (void *)(vh + 1);
    }

    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = pos;
        if ((void *)(ip + 1) > data_end) {
            inc_counter(1);
            return XDP_PASS;
        }

        __u32 key = ip->saddr;
        __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &key);
        if (blocked) {
            inc_counter(0);
            return XDP_DROP;
        }
        __u32 qid = ctx->rx_queue_index;
        __u32 *conf = bpf_map_lookup_elem(&qidconf_map, &qid);
        if (conf) {
            inc_counter(1);
            return bpf_redirect_map(&xsks_map, qid, 0);
        } else {
            inc_counter(1);
            return XDP_PASS;
        }
    }

    if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = pos;
        if ((void *)(ip6 + 1) > data_end) {
            inc_counter(1);
            return XDP_PASS;
        }
        struct in6_addr key6 = ip6->saddr;
        __u8 *blocked6 = bpf_map_lookup_elem(&blocked_ipv6, &key6);
        if (blocked6) {
            inc_counter(0);
            return XDP_DROP;
        }
        __u32 qid = ctx->rx_queue_index;
        __u32 *conf = bpf_map_lookup_elem(&qidconf_map, &qid);
        if (conf) {
            inc_counter(1);
            return bpf_redirect_map(&xsks_map, qid, 0);
        } else {
            inc_counter(1);
            return XDP_PASS;
        }
    }

    inc_counter(1);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
