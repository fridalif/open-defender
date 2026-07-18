package ebpfmonitors

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf -go-package=ebpfmonitors NetworkMonitor bpf/network_monitor.bpf.c -- -I. -O2 -Wall -g

type NetworkEvent struct {
	SrcIP    uint32
	DestPort uint32
}
