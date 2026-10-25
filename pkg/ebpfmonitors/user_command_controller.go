package ebpfmonitors

import "github.com/cilium/ebpf"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir=gobpfs -target bpfel UserCommandController bpf/user_command_controller.bpf.c -- -I./bpf -O2 -Wall -g
const (
	modeLogger    uint32 = 1
	modeBlocker   uint32 = 2
	blockPositive uint32 = 1
	blockNegative uint32 = 2
)

type userCommandControllerConfig struct {
	Mode           string   `yaml:"mode" json:"mode"`
	BlockType      string   `yaml:"block_type" json:"block_type"`
	TargetUsersIDs []string `yaml:"target_users_ids" json:"target_users_ids"`
	TargetCommands []string `yaml:"target_commands" json:"target_commands"`
}

type userKey struct {
	UserNS  uint32
	HostUID uint32
}

type commandKey struct{ Name [64]byte }

type kernelConfig struct {
	Mode        uint32
	BlockType   uint32
	HasUsers    uint32
	HasCommands uint32
}

type execEvent struct {
	TGID       uint32
	PID        uint32
	HostUID    uint32
	UserNS     uint32
	WouldBlock uint32
	Blocked    uint32
	Command    [64]byte
}

type objects struct {
	CheckExec *ebpf.Program `ebpf:"check_exec"`
	Users     *ebpf.Map     `ebpf:"users"`
	Commands  *ebpf.Map     `ebpf:"commands"`
	Settings  *ebpf.Map     `ebpf:"settings"`
	Events    *ebpf.Map     `ebpf:"events"`
}

func (o *objects) Close() {
	if o.CheckExec != nil {
		o.CheckExec.Close()
	}
	if o.Users != nil {
		o.Users.Close()
	}
	if o.Commands != nil {
		o.Commands.Close()
	}
	if o.Settings != nil {
		o.Settings.Close()
	}
	if o.Events != nil {
		o.Events.Close()
	}
}
