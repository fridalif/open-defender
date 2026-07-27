#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    __u32 saddr;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/tcp/tcp_send_reset")
int tp_tcp_send_reset(struct trace_event_raw_tcp_send_reset *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u32 ip = 0;
    ip |= (__u32)ctx->daddr[0] << 24;
    ip |= (__u32)ctx->daddr[1] << 16;
    ip |= (__u32)ctx->daddr[2] << 8;
    ip |= (__u32)ctx->daddr[3];

    __u16 port = 0;
    port |= (__u16)ctx->daddr[4] << 8;
    port |= (__u16)ctx->daddr[5];

    e->saddr = ip;
    e->dport = port;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
