package ebpfmonitors

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,386,arm64,arm -go-package=gobpfs -output-dir=gobpfs NetworkMonitor bpf/network_monitor.bpf.c -- -Ibpf -O2 -Wall -g

type NetworkEvent struct {
	SrcIP    uint32
	DestPort uint32
}

type networkMonitor struct {
}

type NetworkMonitor interface {
}
