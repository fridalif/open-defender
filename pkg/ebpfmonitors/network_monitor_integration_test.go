//go:build integration

package ebpfmonitors

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"open-defender/pkg/config"
	"open-defender/pkg/ebpfmonitors/gobpfs"

	"github.com/cilium/ebpf/rlimit"
)

func closedLoopbackPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func TestRunDetectsResetIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading eBPF requires root, skipping")
	}

	_ = rlimit.RemoveMemlock()
	probe := gobpfs.NetworkMonitorObjects{}
	if err := gobpfs.LoadNetworkMonitorObjects(&probe, nil); err != nil {
		t.Skipf("cannot load eBPF objects (kernel/BTF unsupported): %v", err)
	}
	probe.Close()

	port := closedLoopbackPort(t)

	messages := make(chan string, 100)
	logFunction := func(message string, _ func()) {
		select {
		case messages <- message:
		default:
		}
	}

	cfg := config.EbpfNetworkAntireconConfig{
		Mode:           "logger",
		BlacklistPorts: []uint64{uint64(port)},
		WindowSeconds:  3600,
	}

	ctx, cancel := context.WithCancel(context.Background())
	nm := NewNetworkMonitor(ctx, cancel, cfg, nil, logFunction)

	done := make(chan struct{})
	go func() {
		nm.Run()
		close(done)
	}()

	time.Sleep(300 * time.Millisecond)

	want := fmt.Sprintf("hit blacklisted port %d", port)
	deadline := time.After(10 * time.Second)
	got := false
loop:
	for !got {
		if conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); err == nil {
			conn.Close()
		}

		select {
		case message := <-messages:
			if strings.Contains(message, want) {
				got = true
			}
		case <-deadline:
			break loop
		case <-time.After(200 * time.Millisecond):
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}

	if !got {
		t.Fatalf("did not observe a reset event for port %d", port)
	}
}
