package ebpfmonitors

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir=gobpfs -target bpfel UserCommandController bpf/user_command_controller.bpf.c -- -I./bpf -O2 -Wall -g
