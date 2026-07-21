#include "types.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_SYN_RECV    3
#define TCP_CLOSE       7
#define TCP_LISTEN      10
#define TCP_NEW_SYN_RECV 12

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

	__u16 sport = 0;
	__u32 dip = 0;

	__builtin_memcpy(&sport, &ctx->saddr[2], sizeof(sport));
	__builtin_memcpy(&dip, &ctx->daddr[4], sizeof(dip));

	e->saddr = dip;
	e->dport = sport;

	bpf_ringbuf_submit(e, 0);
	return 0;
}
