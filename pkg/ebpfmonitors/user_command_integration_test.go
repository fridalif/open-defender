//go:build linux && integration

package ebpfmonitors

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	bpf "open-defender/pkg/ebpfmonitors/gobpfs"
)

// Policy is published only for each test child's private user namespace.
// No host namespace is enabled, including in negative mode.
func TestCommandControllerLSM(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires host root, BPF LSM and user namespaces")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                       string
		mode                       uint32
		known, root, denied, event bool
	}{
		{"unknown negative allows", modeBlocker, false, false, false, false},
		{"known negative blocks", modeBlocker, true, false, true, true},
		{"logger records attempt", modeLogger, true, false, false, true},
		{"container root negative allows", modeBlocker, true, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var o commandObjects
			if err := bpf.LoadUserCommandControllerObjects(&o, nil); err != nil {
				t.Fatal(err)
			}
			defer o.Close()
			if err := o.Settings.Update(uint32(0), kernelConfig{Mode: tc.mode, BlockType: blockNegative}, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			reader, err := ringbuf.NewReader(o.Events)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			attached, err := link.AttachLSM(link.LSMOptions{Program: o.Program})
			if err != nil {
				t.Fatal(err)
			}
			defer attached.Close()
			cmd := exec.Command("/bin/sh", "-c", "echo ready; read proceed; exec /bin/true")
			uid := uint32(1)
			if tc.root {
				uid = 0
			}
			cmd.SysProcAttr = &syscall.SysProcAttr{
				Cloneflags:                 syscall.CLONE_NEWUSER,
				UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: 65534, Size: 1}, {ContainerID: 1, HostID: 65533, Size: 1}},
				GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: 65534, Size: 1}, {ContainerID: 1, HostID: 65533, Size: 1}},
				GidMappingsEnableSetgroups: false,
				Credential:                 &syscall.Credential{Uid: uid, Gid: uid, NoSetGroups: true},
			}
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			exited := make(chan struct{})
			var waitErr error
			go func() { waitErr = cmd.Wait(); close(exited) }()
			defer func() { _ = cmd.Process.Kill(); <-exited }()
			ready := make(chan error, 1)
			go func() {
				line, err := bufio.NewReader(stdout).ReadString('\n')
				if err == nil && line != "ready\n" {
					err = fmt.Errorf("unexpected output %q", line)
				}
				ready <- err
			}()
			select {
			case err := <-ready:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("child did not reach barrier")
			}
			pin, err := os.Open(fmt.Sprintf("/proc/%d/ns/user", cmd.Process.Pid))
			if err != nil {
				t.Fatal(err)
			}
			defer pin.Close()
			st, err := pin.Stat()
			if err != nil {
				t.Fatal(err)
			}
			ns := uint32(st.Sys().(*syscall.Stat_t).Ino)
			if tc.known {
				if err := o.Namespaces.Update(ns, uint32(65534), ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := stdin.Write([]byte("go\n")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-exited:
				if (waitErr != nil) != tc.denied {
					t.Fatalf("exec error=%v, denied=%v", waitErr, tc.denied)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("exec did not finish")
			}
			reader.SetDeadline(time.Now().Add(200 * time.Millisecond))
			record, err := reader.Read()
			if !tc.event {
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("expected no event, got record=%v error=%v", record, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var evt execEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
				t.Fatal(err)
			}
			if evt.HostUID != 65533 || evt.EffectiveUID != 65533 || evt.UserNS != ns || evt.WouldBlock != 1 || (evt.Blocked != 0) != tc.denied {
				t.Fatalf("bad event: %+v", evt)
			}
		})
	}
}
