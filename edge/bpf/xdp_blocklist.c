#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1048576);
    __type(key, __u32);
    __type(value, __u8);
} blocked_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

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

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        inc_counter(1);
        return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth + 1);
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

    inc_counter(1);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
