//go:build linux

package ebpfmonitors

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"open-defender/pkg/config"
	bpf "open-defender/pkg/ebpfmonitors/gobpfs"
	"open-defender/pkg/protocol"
	policy "open-defender/pkg/user-command-controller-policy"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -output-dir=gobpfs -target bpfel UserCommandController bpf/user_command_controller.bpf.c -- -I./bpf -O2 -Wall -g
const (
	modeLogger            uint32 = 1
	modeBlocker           uint32 = 2
	blockPositive         uint32 = 1
	blockNegative         uint32 = 2
	namespaceScanInterval        = 150 * time.Second
	namespaceGracePeriod         = 150 * time.Second
	unmappedRootUID       uint32 = ^uint32(0)
)

type execEvent struct {
	TGID, PID, HostUID, UserNS, EffectiveUID, WouldBlock, Blocked, CommandTruncated uint32
	Command                                                                         [64]byte
}

type namespacePolicy struct {
	RootUID    uint32
	_          uint32
	Generation uint64
}

var commandNamespaceGeneration atomic.Uint64

type userKey struct{ UserNS, HostUID uint32 }

// Pin both waiting and active namespaces to prevent inode reuse.
type commandNamespace struct {
	handle  *os.File
	root    uint32
	users   []userKey
	readyAt time.Time
	active  bool
}

type commandRuleMap interface {
	Update(key, value interface{}, flags ebpf.MapUpdateFlags) error
	Delete(key interface{}) error
}

type commandKey struct{ Name [64]byte }
type kernelConfig struct{ Mode, BlockType, HasUsers, HasCommands uint32 }
type commandObjects struct {
	Program    *ebpf.Program `ebpf:"user_command_controller"`
	Users      *ebpf.Map     `ebpf:"users"`
	Namespaces *ebpf.Map     `ebpf:"namespaces"`
	Mounts     *ebpf.Map     `ebpf:"mounts"`
	Commands   *ebpf.Map     `ebpf:"commands"`
	Settings   *ebpf.Map     `ebpf:"settings"`
	Events     *ebpf.Map     `ebpf:"events"`
}

func (o *commandObjects) Close() {
	for _, m := range []*ebpf.Map{o.Users, o.Namespaces, o.Mounts, o.Commands, o.Settings, o.Events} {
		if m != nil {
			_ = m.Close()
		}
	}
	if o.Program != nil {
		_ = o.Program.Close()
	}
}

type UserCommandControllerMonitor interface{ Run() error }
type userCommandControllerMonitor struct {
	ctx    context.Context
	cfg    config.UserCommandExecutionController
	report func(protocol.AlertEvent)
}

func NewUserCommandControllerMonitor(ctx context.Context, cfg config.UserCommandExecutionController, report func(protocol.AlertEvent)) UserCommandControllerMonitor {
	return &userCommandControllerMonitor{ctx: ctx, cfg: cfg, report: report}
}

func discoverCommandNamespaces(ctx context.Context, uids []uint32) (map[uint32]*commandNamespace, error) {
	return discoverCommandContexts(ctx, uids, false)
}

// Docker gives each container a mount namespace even when userns is shared
// with the host. Its independent readiness prevents host policy from applying
// to a container before that container's setup grace period has expired.
func discoverCommandContexts(ctx context.Context, uids []uint32, mounts bool) (map[uint32]*commandNamespace, error) {
	namespacePath := "ns/user"
	if mounts {
		namespacePath = "ns/mnt"
	}
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	states := make(map[uint32]*commandNamespace)
	for _, dir := range dirs {
		if ctx.Err() != nil {
			closeNamespaces(states)
			return nil, ctx.Err()
		}
		if _, err := strconv.ParseUint(dir.Name(), 10, 32); err != nil {
			continue
		}
		proc := filepath.Join("/proc", dir.Name())
		// Keep the proc directory open so PID reuse cannot mix two processes.
		procFD, err := os.Open(proc)
		if err != nil {
			continue
		}
		base := fmt.Sprintf("/proc/self/fd/%d", procFD.Fd())
		handle, err := os.Open(filepath.Join(base, namespacePath))
		if err != nil {
			_ = procFD.Close()
			continue
		}
		st, err := handle.Stat()
		if err != nil {
			_ = handle.Close()
			_ = procFD.Close()
			continue
		}
		ino := st.Sys().(*syscall.Stat_t).Ino
		if ino > 0xffffffff {
			_ = handle.Close()
			_ = procFD.Close()
			continue
		}
		ns := uint32(ino)
		if _, exists := states[ns]; exists {
			_ = handle.Close()
			_ = procFD.Close()
			continue
		}
		if mounts {
			states[ns] = &commandNamespace{handle: handle}
			_ = procFD.Close()
			continue
		}
		mapping, err := os.ReadFile(filepath.Join(base, "uid_map"))
		// Verify that the process did not switch namespaces while reading uid_map.
		after, statErr := os.Stat(filepath.Join(base, "ns/user"))
		_ = procFD.Close()
		if err != nil || statErr != nil || !os.SameFile(st, after) {
			_ = handle.Close()
			continue
		}
		// An empty uid_map can still be initialized. Once nonempty, Linux
		// permits no further writes, so the cached root exemption is stable.
		if len(bytes.Fields(mapping)) == 0 {
			_ = handle.Close()
			continue
		}
		root, users, err := commandNamespaceRules(ns, string(mapping), uids)
		if err != nil {
			_ = handle.Close()
			continue
		}
		states[ns] = &commandNamespace{handle: handle, root: root, users: users}
	}
	return states, nil
}

func (m *userCommandControllerMonitor) Run() error {
	if m.cfg.Mode == "" || m.cfg.Mode == "disabled" {
		return nil
	}
	if err := m.cfg.Validate(); err != nil {
		return err
	}
	// uid_map must be read relative to the initial host user namespace.
	if os.Geteuid() != 0 {
		return fmt.Errorf("user_command_controller requires host root")
	}
	raw, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return err
	}
	if len(bytes.Fields(raw)) != 3 || string(bytes.Join(bytes.Fields(raw), []byte(" "))) != "0 0 4294967295" {
		return fmt.Errorf("user_command_controller must run in the initial host user namespace")
	}
	uids, _ := policy.ParseUIDs(m.cfg.TargetUsersIDs)
	commands, _ := policy.NormalizeCommands(m.cfg.TargetCommands)
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("user_command_controller memlock: %w", err)
	}
	var o commandObjects
	defer o.Close()
	if err := bpf.LoadUserCommandControllerObjects(&o, nil); err != nil {
		return fmt.Errorf("user_command_controller load: %w", err)
	}
	for _, command := range commands {
		var key commandKey
		copy(key.Name[:], command)
		if err := o.Commands.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithCancel(m.ctx)
	defer cancel()
	current := make(map[uint32]*commandNamespace)
	defer closeNamespaces(current)
	currentMounts := make(map[uint32]*commandNamespace)
	defer closeNamespaces(currentMounts)
	scan := func() error {
		desired, err := discoverCommandNamespaces(ctx, uids)
		if err != nil {
			return err
		}
		defer closeNamespaces(desired)
		if err := syncCommandNamespaces(o.Users, o.Namespaces, current, desired); err != nil {
			return err
		}
		mounts, err := discoverCommandContexts(ctx, nil, true)
		if err != nil {
			return err
		}
		defer closeNamespaces(mounts)
		return syncCommandNamespaces(nil, o.Mounts, currentMounts, mounts)
	}
	if err := scan(); err != nil {
		return fmt.Errorf("user_command_controller namespaces: %w", err)
	}
	cfg := kernelConfig{Mode: modeLogger, BlockType: blockPositive}
	if m.cfg.Mode == "blocker" {
		cfg.Mode = modeBlocker
	}
	if m.cfg.BlockType == "negative" {
		cfg.BlockType = blockNegative
	}
	if len(uids) > 0 {
		cfg.HasUsers = 1
	}
	if len(commands) > 0 {
		cfg.HasCommands = 1
	}
	if err := o.Settings.Update(uint32(0), cfg, ebpf.UpdateAny); err != nil {
		return err
	}
	reader, err := ringbuf.NewReader(o.Events)
	if err != nil {
		return err
	}
	defer reader.Close()
	attached, err := link.AttachLSM(link.LSMOptions{Program: o.Program})
	if err != nil {
		return fmt.Errorf("user_command_controller attach LSM: %w", err)
	}
	defer attached.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	// Join before closing maps/namespace FDs.
	defer func() { cancel(); wg.Wait() }()
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(namespaceScanInterval)
		defer ticker.Stop()
		activationTimer := time.NewTimer(namespaceGracePeriod)
		defer activationTimer.Stop()
		var activationC <-chan time.Time
		resetActivation := func() {
			activationTimer.Stop()
			activationC = nil
			if deadline, ok := nextCommandActivation(current, currentMounts); ok {
				activationTimer.Reset(time.Until(deadline))
				activationC = activationTimer.C
			}
		}
		resetActivation()
		for {
			select {
			case <-ctx.Done():
				_ = attached.Close()
				_ = reader.Close()
				return
			case <-ticker.C:
				if err := scan(); err != nil {
					log.Printf("user_command_controller namespace update failed; detaching: %v", err)
					cancel()
				}
				resetActivation()
			case <-activationC:
				if err := activateCommandNamespaces(o.Users, o.Namespaces, current, time.Now()); err != nil {
					log.Printf("user_command_controller namespace activation failed; detaching: %v", err)
					cancel()
				}
				if err := activateCommandNamespaces(nil, o.Mounts, currentMounts, time.Now()); err != nil {
					log.Printf("user_command_controller container activation failed; detaching: %v", err)
					cancel()
				}
				resetActivation()
			}
		}
	}()
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("user_command_controller read: %w", err)
		}
		event, err := decodeCommandEvent(record.RawSample, m.cfg.Mode)
		if err != nil {
			log.Printf("user_command_controller: %v", err)
			continue
		}
		if event != nil && m.report != nil {
			m.report(*event)
		}
	}
}

func closeNamespaces(states map[uint32]*commandNamespace) {
	for _, state := range states {
		_ = state.handle.Close()
	}
}

// Remove readiness first; publish it last. A failed update never exposes
// incomplete rules to the enforcing hook. The caller detaches on map errors.
func syncCommandNamespaces(users, namespaces commandRuleMap, current, desired map[uint32]*commandNamespace) error {
	for ns, state := range current {
		if _, exists := desired[ns]; exists {
			continue
		}
		if state.active {
			if err := namespaces.Delete(ns); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return err
			}
			for _, key := range state.users {
				if err := users.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					return err
				}
			}
		}
		_ = state.handle.Close()
		delete(current, ns)
	}
	for ns, state := range desired {
		if _, exists := current[ns]; exists {
			continue
		}
		if state.readyAt.IsZero() {
			state.readyAt = time.Now().Add(namespaceGracePeriod)
		}
		current[ns] = state
		delete(desired, ns)
	}
	return activateCommandNamespaces(users, namespaces, current, time.Now())
}

func activateCommandNamespaces(users, namespaces commandRuleMap, current map[uint32]*commandNamespace, now time.Time) error {
	for ns, state := range current {
		if state.active || now.Before(state.readyAt) {
			continue
		}
		for _, key := range state.users {
			if err := users.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
				return err
			}
		}
		generation := commandNamespaceGeneration.Add(1)
		if generation == 0 {
			return fmt.Errorf("namespace generation exhausted")
		}
		if err := namespaces.Update(ns, namespacePolicy{RootUID: state.root, Generation: generation}, ebpf.UpdateAny); err != nil {
			return err
		}
		state.active = true
	}
	return nil
}

func nextCommandActivation(groups ...map[uint32]*commandNamespace) (time.Time, bool) {
	var earliest time.Time
	for _, current := range groups {
		for _, state := range current {
			if !state.active && (earliest.IsZero() || state.readyAt.Before(earliest)) {
				earliest = state.readyAt
			}
		}
	}
	return earliest, !earliest.IsZero()
}

func commandNamespaceRules(ns uint32, mapping string, uids []uint32) (uint32, []userKey, error) {
	root, found, err := policy.HostUID(0, mapping)
	if err != nil {
		return 0, nil, err
	}
	if !found {
		// (uid_t)-1 cannot identify a real user. This namespace has no root
		// mapping, but its other users must still be subject to policy.
		root = unmappedRootUID
	}
	var users []userKey
	for _, uid := range uids {
		host, found, err := policy.HostUID(uid, mapping)
		if err != nil {
			return 0, nil, err
		}
		if found {
			users = append(users, userKey{UserNS: ns, HostUID: host})
		}
	}
	return root, users, nil
}

func decodeCommandEvent(sample []byte, mode string) (*protocol.AlertEvent, error) {
	var evt execEvent
	if len(sample) != binary.Size(evt) {
		return nil, fmt.Errorf("invalid exec event size %d", len(sample))
	}
	if err := binary.Read(bytes.NewReader(sample), binary.LittleEndian, &evt); err != nil {
		return nil, err
	}
	if evt.HostUID == 0 || evt.EffectiveUID == 0 || evt.WouldBlock == 0 {
		return nil, nil
	}
	result, severity := "logged", protocol.SeverityCritical
	if mode == "blocker" {
		if evt.Blocked == 0 {
			return nil, nil
		}
		result, severity = "blocked", protocol.SeverityHigh
	}
	command := string(bytes.TrimRight(evt.Command[:], "\x00"))
	if evt.CommandTruncated != 0 {
		command += "..."
	}
	return &protocol.AlertEvent{
		Source: protocol.SourceUserCommandController, Severity: severity,
		Message: fmt.Sprintf("user_command_controller -> %s command %q uid=%d euid=%d userns=%d pid=%d tid=%d", result, command, evt.HostUID, evt.EffectiveUID, evt.UserNS, evt.TGID, evt.PID),
		Details: map[string]any{"result": result, "command": command, "uid": evt.HostUID, "effective_uid": evt.EffectiveUID, "user_namespace": evt.UserNS, "pid": evt.TGID, "tid": evt.PID, "mode": mode},
	}, nil
}
