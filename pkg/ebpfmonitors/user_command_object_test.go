//go:build linux

package ebpfmonitors

import (
	"encoding/binary"
	"testing"

	bpf "open-defender/pkg/ebpfmonitors/gobpfs"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestEmbeddedCommandObject(t *testing.T) {
	spec, err := bpf.LoadUserCommandController()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][2]uint32{"users": {8, 1}, "namespaces": {4, 16}, "mounts": {4, 16}, "commands": {64, 1}, "settings": {4, 16}} {
		m := spec.Maps[name]
		if m == nil || m.KeySize != want[0] || m.ValueSize != want[1] {
			t.Fatalf("bad map %s: %+v", name, m)
		}
	}
	program := spec.Programs["user_command_controller"]
	if program == nil || program.Type != ebpf.LSM || program.AttachType != ebpf.AttachLSMMac {
		t.Fatalf("wrong program: %+v", program)
	}
	// Check the record size actually reserved by the embedded BPF instructions.
	found := false
	for i, ins := range program.Instructions {
		if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnRingbufReserve) {
			if i < 2 || program.Instructions[i-2].Dst != asm.R2 || program.Instructions[i-2].Constant != int64(binary.Size(execEvent{})) {
				t.Fatal("BPF ring buffer record size differs from Go decoder")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("BPF program does not reserve events")
	}
}
