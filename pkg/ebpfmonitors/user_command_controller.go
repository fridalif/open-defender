//go:build Linux

package ebpfmonitors

import (
	"context"
	"fmt"
	"log"
	"open-defender/pkg/config"
	usercommandcontrollerpolicy "open-defender/pkg/user-command-controller-policy"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
)

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

type UserCommandControllerMonitor interface {
	Run() error
}

type userCommandControllerMonitor struct {
	ctx         context.Context
	cancel      context.CancelFunc
	cfg         config.UserCommandExecutionController
	logFunction func(message string)
}

func NewUserCommandControllerMonitor(ctx context.Context, cancel context.CancelFunc, cfg config.UserCommandExecutionController, logFn func(message string, isNewBan bool)) UserCommandControllerMonitor {
	return &userCommandControllerMonitor{
		ctx:    ctx,
		cancel: cancel,
		cfg:    cfg,
		logFunction: func(message string) {
			logFn(message, true)
		},
	}
}

func (uccm *userCommandControllerMonitor) namespaceInode(path string) (uint32, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	linuxStat, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("cannot inspect namespace inode at %s", path)
	}
	if linuxStat.Ino > 0xffffffff {
		return 0, fmt.Errorf("namespace inode out of range at %s", path)
	}
	return uint32(linuxStat.Ino), nil
}

func (uccm *userCommandControllerMonitor) discoverUserRules(uids []uint32) (map[userKey]struct{}, error) {
	result := make(map[userKey]struct{})
	if len(uids) == 0 {
		return result, nil
	}

	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	seen := make(map[uint32]struct{})
	var inaccessible int
	for _, dir := range dirs {
		if _, err := strconv.Atoi(dir.Name()); err != nil {
			continue
		}
		proc := filepath.Join("/proc", dir.Name())
		inode, err := uccm.namespaceInode(filepath.Join(proc, "ns/user"))
		if err != nil {
			inaccessible++
			continue
		}
		if _, ok := seen[inode]; ok {
			continue
		}
		mapping, err := os.ReadFile(filepath.Join(proc, "uid_map"))
		if err != nil {
			inaccessible++
			continue
		}
		seen[inode] = struct{}{}
		for _, uid := range uids {
			hostUID, found, err := usercommandcontrollerpolicy.HostUID(uid, string(mapping))
			if err != nil {
				return nil, fmt.Errorf("%s uid_map: %w", proc, err)
			}
			if found {
				result[userKey{UserNS: inode, HostUID: hostUID}] = struct{}{}
			}
		}
	}
	if inaccessible > 0 {
		log.Printf("WARNING: %d /proc entries could not be read (exit/permission); some rules may lag", inaccessible)
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("no user namespaces readable via /proc")
	}
	return result, nil
}

func (uccm *userCommandControllerMonitor) Run() error {
	return nil
}
