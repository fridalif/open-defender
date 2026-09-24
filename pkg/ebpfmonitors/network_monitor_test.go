package ebpfmonitors

import (
	"bytes"
	"context"
	"errors"
	"log"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"open-defender/pkg/banpool/mocks"
	"open-defender/pkg/config"

	"go.uber.org/mock/gomock"
)

func newNetworkMonitor(t *testing.T, cfg config.EbpfNetworkAntireconConfig, bp *mocks.MockBanPool, logFunction func(string, bool)) *networkMonitor {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &networkMonitor{ctx: ctx, cancel: cancel, cfg: cfg, bp: bp, logFunction: logFunction}
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	original := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(original) })
	return &buf
}

func TestNewNetworkMonitor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	nm := NewNetworkMonitor(ctx, cancel, config.EbpfNetworkAntireconConfig{}, nil, func(string, bool) {})
	if nm == nil {
		t.Fatal("NewNetworkMonitor() returned nil")
	}
}

func TestClearMapStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	nm := &networkMonitor{ctx: ctx}
	done := make(chan struct{})

	go func() {
		nm.clearMap(3600, &sync.Map{})
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("clearMap did not stop after context cancellation")
	}
}

func TestParseEvent(t *testing.T) {
	// 192.168.1.5:80, порт в network byte order (0x0050), плюс паддинг структуры.
	sample := []byte{192, 168, 1, 5, 0x00, 0x50, 0x00, 0x00}
	event, ok := parseEvent(sample)
	if !ok {
		t.Fatal("parseEvent() rejected a valid sample")
	}
	if event.SrcIP != 0xC0A80105 {
		t.Errorf("SrcIP = %#x, want 0xC0A80105", event.SrcIP)
	}
	if event.DestPort != 80 {
		t.Errorf("DestPort = %d, want 80", event.DestPort)
	}

	if _, ok := parseEvent([]byte{1, 2, 3}); ok {
		t.Error("parseEvent() accepted a short sample")
	}
}

func TestIPString(t *testing.T) {
	if got := ipString(0xC0A80105); got != "192.168.1.5" {
		t.Errorf("ipString() = %q, want 192.168.1.5", got)
	}
	if got := ipString(0); got != "0.0.0.0" {
		t.Errorf("ipString() = %q, want 0.0.0.0", got)
	}
}

func TestPortsToSet(t *testing.T) {
	set := portsToSet([]uint64{22, 80, 65535})
	if len(set) != 3 {
		t.Fatalf("len = %d, want 3", len(set))
	}
	for _, port := range []uint16{22, 80, 65535} {
		if _, ok := set[port]; !ok {
			t.Errorf("port %d missing", port)
		}
	}
}

func TestReport(t *testing.T) {
	t.Run("logger does not ban", func(t *testing.T) {
		var gotMessage string
		logFunction := func(message string, isNewBan bool) {
			gotMessage = message
			if isNewBan {
				t.Error("logger unexpectedly reported a new ban")
			}
		}
		nm := newNetworkMonitor(t, config.EbpfNetworkAntireconConfig{Mode: "logger"}, nil, logFunction)
		nm.report("1.2.3.4", "network_antirecon -> scan")
		if gotMessage != "network_antirecon -> scan" {
			t.Errorf("message = %q", gotMessage)
		}
	})

	t.Run("blocker bans", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		bp := mocks.NewMockBanPool(ctrl)
		bp.EXPECT().BanIP(gomock.Any(), "1.2.3.4", uint64(60)).Return(false, nil)

		logFunction := func(_ string, isNewBan bool) {
			if !isNewBan {
				t.Error("blocker did not report a new ban")
			}
		}
		nm := newNetworkMonitor(t, config.EbpfNetworkAntireconConfig{Mode: "blocker", BanSeconds: 60}, bp, logFunction)
		nm.report("1.2.3.4", "network_antirecon -> scan")
	})

	t.Run("blocker ban error", func(t *testing.T) {
		buf := captureLog(t)
		ctrl := gomock.NewController(t)
		bp := mocks.NewMockBanPool(ctrl)
		bp.EXPECT().BanIP(gomock.Any(), "1.2.3.4", uint64(60)).Return(false, errors.New("boom"))

		logFunction := func(_ string, _ bool) { t.Error("alert emitted after ban error") }
		nm := newNetworkMonitor(t, config.EbpfNetworkAntireconConfig{Mode: "blocker", BanSeconds: 60}, bp, logFunction)
		nm.report("1.2.3.4", "network_antirecon -> scan")
		if !strings.Contains(buf.String(), "boom") {
			t.Errorf("log = %q, want it to contain the ban error", buf.String())
		}
	})
}

func TestClearMap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	nm := &networkMonitor{ctx: ctx}
	m := &sync.Map{}
	m.Store("1.2.3.4", portSet{22: {}})
	nm.clearMap(0, m) // отменённый контекст -> выход без сна
}

func TestClearMapRemovesEntries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	nm := &networkMonitor{ctx: ctx}
	m := &sync.Map{}
	m.Store("1.2.3.4", portSet{22: {}})
	done := make(chan struct{})
	go func() {
		nm.clearMap(0, m)
		close(done)
	}()

	deadline := time.After(time.Second)
	for {
		_, exists := m.Load("1.2.3.4")
		if !exists {
			cancel()
			<-done
			return
		}
		select {
		case <-deadline:
			cancel()
			t.Fatal("clearMap() did not remove map entries")
		default:
			runtime.Gosched()
		}
	}
}

func TestRunDisabled(t *testing.T) {
	alerted := false
	logFunction := func(string, bool) { alerted = true }
	nm := newNetworkMonitor(t, config.EbpfNetworkAntireconConfig{Mode: "disabled"}, nil, logFunction)
	if err := nm.Run(); err != nil {
		t.Fatalf("error = %v", err)
	}
	if alerted {
		t.Error("disabled monitor produced an alert")
	}
}
