#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

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
int tp_tcp_send_reset(void *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u16 sport = 0;
    __u32 daddr = 0;

    bpf_core_read(&sport, sizeof(sport), (void *)ctx + offsetof(struct trace_event_raw_tcp_send_reset, saddr[2]));
    bpf_core_read(&daddr, sizeof(daddr), (void *)ctx + offsetof(struct trace_event_raw_tcp_send_reset, daddr[4]));

    e->saddr = daddr;
    e->dport = sport;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
