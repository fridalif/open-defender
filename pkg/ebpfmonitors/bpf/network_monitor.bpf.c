#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define ETH_P_IP 0x0800

struct event {
    __u32 saddr;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("xdp")
int xdp_network_monitor(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    struct tcphdr *tcp = (struct tcphdr *)((unsigned char *)ip + ip_hdr_len);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (!(tcp->syn && !tcp->ack))
        return XDP_PASS;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return XDP_PASS;

    e->saddr = bpf_ntohl(ip->saddr);
    e->dport = bpf_ntohs(tcp->dest);

    bpf_ringbuf_submit(e, 0);
    return XDP_PASS;
}
