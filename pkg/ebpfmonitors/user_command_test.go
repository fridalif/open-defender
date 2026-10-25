//go:build linux

package ebpfmonitors

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"open-defender/pkg/protocol"
)

func TestCommandEventExport(t *testing.T) {
	for _, tc := range []struct {
		name, mode                string
		uid, euid, would, blocked uint32
		result, severity          string
	}{
		{"logger selected", "logger", 1000, 1000, 1, 0, "logged", protocol.SeverityCritical},
		{"blocker denied", "blocker", 1000, 1000, 1, 1, "blocked", protocol.SeverityHigh},
		{"logger ignored", "logger", 1000, 1000, 0, 0, "", ""},
		{"blocker allowed", "blocker", 1000, 1000, 1, 0, "", ""},
		{"real root", "logger", 0, 1000, 1, 0, "", ""},
		{"effective root", "blocker", 1000, 0, 1, 1, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evt := execEvent{HostUID: tc.uid, EffectiveUID: tc.euid, WouldBlock: tc.would, Blocked: tc.blocked, TGID: 42, PID: 43, UserNS: 99}
			copy(evt.Command[:], "curl")
			var raw bytes.Buffer
			if err := binary.Write(&raw, binary.LittleEndian, evt); err != nil {
				t.Fatal(err)
			}
			got, err := decodeCommandEvent(raw.Bytes(), tc.mode)
			if err != nil {
				t.Fatal(err)
			}
			if tc.result == "" {
				if got != nil {
					t.Fatalf("unexpected event: %+v", got)
				}
				return
			}
			if got == nil || got.Source != protocol.SourceUserCommandController || got.Severity != tc.severity || got.Details["result"] != tc.result || got.Details["command"] != "curl" || got.Details["pid"] != uint32(42) {
				t.Fatalf("bad event: %+v", got)
			}
		})
	}
	for _, size := range []int{0, 92, 95, 97, 100} {
		if _, err := decodeCommandEvent(make([]byte, size), "logger"); err == nil {
			t.Fatalf("accepted size %d", size)
		}
	}
}

type commandMapFake struct {
	name string
	ops  *[]string
	fail bool
}

func (m commandMapFake) Update(key, value interface{}, flags ebpf.MapUpdateFlags) error {
	*m.ops = append(*m.ops, m.name+" update")
	if m.fail {
		return errors.New("map full")
	}
	return nil
}
func (m commandMapFake) Delete(key interface{}) error {
	*m.ops = append(*m.ops, m.name+" delete")
	if m.fail {
		return errors.New("map unavailable")
	}
	return nil
}
func namespaceForTest(t *testing.T) *commandNamespace {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "namespace")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return &commandNamespace{handle: f, root: 100000, users: []userKey{{99, 101000}}, readyAt: time.Now().Add(-time.Second)}
}
func TestNamespacePublicationOrder(t *testing.T) {
	var ops []string
	current := map[uint32]*commandNamespace{}
	desired := map[uint32]*commandNamespace{99: namespaceForTest(t)}
	users, namespaces := commandMapFake{"users", &ops, false}, commandMapFake{"namespaces", &ops, false}
	if err := syncCommandNamespaces(users, namespaces, current, desired); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ops, []string{"users update", "namespaces update"}) || len(desired) != 0 || len(current) != 1 {
		t.Fatalf("unsafe publication: %v", ops)
	}
	ops = nil
	if err := syncCommandNamespaces(users, namespaces, current, map[uint32]*commandNamespace{}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ops, []string{"namespaces delete", "users delete"}) || len(current) != 0 {
		t.Fatalf("unsafe removal: %v", ops)
	}
}
func TestNamespaceRuleFailureRemainsUnknown(t *testing.T) {
	var ops []string
	current := map[uint32]*commandNamespace{}
	desired := map[uint32]*commandNamespace{99: namespaceForTest(t)}
	if err := syncCommandNamespaces(commandMapFake{"users", &ops, true}, commandMapFake{"namespaces", &ops, false}, current, desired); err == nil {
		t.Fatal("expected error")
	}
	if !reflect.DeepEqual(ops, []string{"users update"}) || len(current) != 1 || len(desired) != 0 || current[99].active {
		t.Fatalf("published incomplete rules: %v", ops)
	}
}
func TestNamespaceRemovalFailurePreservesPin(t *testing.T) {
	var ops []string
	current := map[uint32]*commandNamespace{99: namespaceForTest(t)}
	current[99].active = true
	if err := syncCommandNamespaces(commandMapFake{"users", &ops, false}, commandMapFake{"namespaces", &ops, true}, current, map[uint32]*commandNamespace{}); err == nil {
		t.Fatal("expected error")
	}
	if !reflect.DeepEqual(ops, []string{"namespaces delete"}) || len(current) != 1 {
		t.Fatalf("lost namespace pin while active: %v", ops)
	}
	if _, err := current[99].handle.Stat(); err != nil {
		t.Fatalf("pin closed: %v", err)
	}
}

type namespacePolicyMapFake struct {
	values []namespacePolicy
}

func (m *namespacePolicyMapFake) Update(key, value interface{}, flags ebpf.MapUpdateFlags) error {
	m.values = append(m.values, value.(namespacePolicy))
	return nil
}
func (m *namespacePolicyMapFake) Delete(key interface{}) error { return nil }

func TestRepublishedNamespaceHasNewGeneration(t *testing.T) {
	var ops []string
	users := commandMapFake{"users", &ops, false}
	namespaces := &namespacePolicyMapFake{}
	current := map[uint32]*commandNamespace{}
	if err := syncCommandNamespaces(users, namespaces, current, map[uint32]*commandNamespace{99: namespaceForTest(t)}); err != nil {
		t.Fatal(err)
	}
	if err := syncCommandNamespaces(users, namespaces, current, map[uint32]*commandNamespace{}); err != nil {
		t.Fatal(err)
	}
	if err := syncCommandNamespaces(users, namespaces, current, map[uint32]*commandNamespace{99: namespaceForTest(t)}); err != nil {
		t.Fatal(err)
	}
	if len(namespaces.values) != 2 || namespaces.values[0].Generation == 0 || namespaces.values[0].Generation == namespaces.values[1].Generation {
		t.Fatalf("unsafe namespace generations: %+v", namespaces.values)
	}
	if namespaces.values[0].RootUID != 100000 || namespaces.values[1].RootUID != 100000 {
		t.Fatal("lost root exemption")
	}
	if binary.Size(namespacePolicy{}) != 16 {
		t.Fatal("namespace policy ABI mismatch")
	}
}

func TestTruncatedCommandEvent(t *testing.T) {
	evt := execEvent{HostUID: 1000, EffectiveUID: 1000, WouldBlock: 1, Blocked: 1, CommandTruncated: 1}
	copy(evt.Command[:], "long-command-prefix")
	var raw bytes.Buffer
	if err := binary.Write(&raw, binary.LittleEndian, evt); err != nil {
		t.Fatal(err)
	}
	event, err := decodeCommandEvent(raw.Bytes(), "blocker")
	if err != nil {
		t.Fatal(err)
	}
	if event == nil || event.Details["command"] != "long-command-prefix..." || event.Severity != protocol.SeverityHigh {
		t.Fatalf("incorrect truncated event: %+v", event)
	}
}

func TestNamespaceWithoutRootMapping(t *testing.T) {
	root, users, err := commandNamespaceRules(99, "1000 101000 1\n", []uint32{0, 1000})
	if err != nil || root != unmappedRootUID || !reflect.DeepEqual(users, []userKey{{99, 101000}}) {
		t.Fatalf("namespace without root lost policy: root=%d users=%v err=%v", root, users, err)
	}
	state := namespaceForTest(t)
	state.root, state.users = root, users
	var ops []string
	namespaces := &namespacePolicyMapFake{}
	if err := syncCommandNamespaces(commandMapFake{"users", &ops, false}, namespaces, map[uint32]*commandNamespace{}, map[uint32]*commandNamespace{99: state}); err != nil {
		t.Fatal(err)
	}
	if len(namespaces.values) != 1 || namespaces.values[0].RootUID != unmappedRootUID || !state.active {
		t.Fatal("namespace without root remained unrestricted")
	}
}

func TestNewContainerGraceWithActiveHostNamespace(t *testing.T) {
	var ops []string
	mounts := commandMapFake{"mounts", &ops, false}
	host := namespaceForTest(t)
	host.active = true
	current := map[uint32]*commandNamespace{1: host}
	container := namespaceForTest(t)
	container.users = nil
	container.readyAt = time.Time{}
	before := time.Now()
	if err := syncCommandNamespaces(nil, mounts, current, map[uint32]*commandNamespace{1: namespaceForTest(t), 2: container}); err != nil {
		t.Fatal(err)
	}
	deadline := container.readyAt
	if len(ops) != 0 || container.active || deadline.Before(before.Add(150*time.Second)) {
		t.Fatalf("new container enabled too early: %v %+v", ops, container)
	}
	if next, ok := nextCommandActivation(current); !ok || !next.Equal(deadline) {
		t.Fatal("missing container activation timer")
	}
	if err := syncCommandNamespaces(nil, mounts, current, map[uint32]*commandNamespace{1: namespaceForTest(t), 2: namespaceForTest(t)}); err != nil || !container.readyAt.Equal(deadline) {
		t.Fatal("rescan reset the grace period", err)
	}
	if err := activateCommandNamespaces(nil, mounts, current, deadline.Add(-time.Nanosecond)); err != nil || len(ops) != 0 {
		t.Fatal("container activated before deadline", err)
	}
	if err := activateCommandNamespaces(nil, mounts, current, deadline); err != nil || !container.active || !reflect.DeepEqual(ops, []string{"mounts update"}) {
		t.Fatal("container did not activate at deadline", ops, err)
	}
	if _, ok := nextCommandActivation(current); ok {
		t.Fatal("active container still pending")
	}
}

func TestPendingNamespaceRemovedWithoutPublishing(t *testing.T) {
	state := namespaceForTest(t)
	state.readyAt = time.Now().Add(namespaceGracePeriod)
	current := map[uint32]*commandNamespace{99: state}
	var ops []string
	if err := syncCommandNamespaces(nil, commandMapFake{"mounts", &ops, false}, current, map[uint32]*commandNamespace{}); err != nil || len(ops) != 0 || len(current) != 0 {
		t.Fatal("removed pending namespace touched policy", ops, err)
	}
	if _, err := state.handle.Stat(); err == nil {
		t.Fatal("removed namespace pin still open")
	}
}
