#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

struct event {
	__u32 saddr; 
	__u16 dport; 
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/tcp_v4_send_reset")
int BPF_KPROBE(kprobe_tcp_v4_send_reset, struct sock *sk, struct sk_buff *skb)
{
	if (!skb)
		return 0;

	void *head;
	__u16 net_off, trans_off;

	if (bpf_core_read(&head, sizeof(head), &skb->head))
		return 0;
	if (bpf_core_read(&net_off, sizeof(net_off), &skb->network_header))
		return 0;
	if (bpf_core_read(&trans_off, sizeof(trans_off), &skb->transport_header))
		return 0;

	struct iphdr *iph = (struct iphdr *)(head + net_off);
	struct tcphdr *tcph = (struct tcphdr *)(head + trans_off);

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	bpf_core_read(&e->saddr, sizeof(e->saddr), &iph->saddr);
	bpf_core_read(&e->dport, sizeof(e->dport), &tcph->dest);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/udp_rcv")
int BPF_KPROBE(kprobe_udp_rcv, struct sk_buff *skb)
{
	if (!skb)
		return 0;

	void *head;
	__u16 net_off, trans_off;

	if (bpf_core_read(&head, sizeof(head), &skb->head))
		return 0;
	if (bpf_core_read(&net_off, sizeof(net_off), &skb->network_header))
		return 0;
	if (bpf_core_read(&trans_off, sizeof(trans_off), &skb->transport_header))
		return 0;

	struct iphdr *iph = (struct iphdr *)(head + net_off);
	struct udphdr *udph = (struct udphdr *)(head + trans_off);

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	bpf_core_read(&e->saddr, sizeof(e->saddr), &iph->saddr);
	bpf_core_read(&e->dport, sizeof(e->dport), &udph->dest);

	bpf_ringbuf_submit(e, 0);
	return 0;
}