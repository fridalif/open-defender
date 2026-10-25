//go:build linux

package ebpfmonitors

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"reflect"
	"testing"

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
	for _, size := range []int{0, 91, 93, 100} {
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
	return &commandNamespace{handle: f, root: 100000, users: []userKey{{99, 101000}}}
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
	if !reflect.DeepEqual(ops, []string{"users update"}) || len(current) != 0 || len(desired) != 1 {
		t.Fatalf("published incomplete rules: %v", ops)
	}
}
func TestNamespaceRemovalFailurePreservesPin(t *testing.T) {
	var ops []string
	current := map[uint32]*commandNamespace{99: namespaceForTest(t)}
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
