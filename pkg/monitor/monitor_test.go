package monitor

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"open-defender/pkg/banpool/mocks"
	"open-defender/pkg/config"

	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"go.uber.org/mock/gomock"
)

func newHub(t *testing.T, cfg *config.Config, bp *mocks.MockBanPool) *monitorHub {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &monitorHub{cfg: cfg, ctx: ctx, cancel: cancel, wg: new(sync.WaitGroup), bp: bp}
}

func stubStartSource(t *testing.T, fn func(context.Context, *config.BaseFields, chan<- string) error) {
	t.Helper()
	original := startSource
	startSource = fn
	t.Cleanup(func() { startSource = original })
}

func feedLines(lines ...string) func(context.Context, *config.BaseFields, chan<- string) error {
	return func(ctx context.Context, bm *config.BaseFields, out chan<- string) error {
		go func() {
			for _, line := range lines {
				out <- line
			}
			close(out)
		}()
		return nil
	}
}

func syncGoRun(t *testing.T) {
	t.Helper()
	original := goRun
	goRun = func(f func()) { f() }
	t.Cleanup(func() { goRun = original })
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	original := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(original) })
	return &buf
}

func TestNew(t *testing.T) {
	ctrl := gomock.NewController(t)
	if New(config.New(), mocks.NewMockBanPool(ctrl), t.TempDir()+"/config.yaml") == nil {
		t.Fatal("New() returned nil")
	}
}

func TestGetIP(t *testing.T) {
	re := regexp.MustCompile(`from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})`)
	mh := newHub(t, config.New(), nil)

	if ip, ok := mh.getIp(re, "from 10.20.30.40 port 22"); !ok || ip != "10.20.30.40" {
		t.Fatalf("getIp() = %q, %v", ip, ok)
	}
	if _, ok := mh.getIp(re, "nothing here"); ok {
		t.Error("getIp() matched a non-matching line")
	}

	noGroup := regexp.MustCompile(`from ((?:\d{1,3}\.){3}\d{1,3})`)
	if _, ok := mh.getIp(noGroup, "from 10.20.30.40"); ok {
		t.Error("getIp() matched without an ip group")
	}
}

func TestClearMaps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mh := newHub(t, config.New(), nil)
	m := &sync.Map{}
	m.Store("k", uint64(1))
	mh.clearMaps(ctx, 0, m)
}

func TestCheckLimits(t *testing.T) {
	tests := []struct {
		name    string
		value   float64
		limits  config.ResourceFields
		wantLog string
	}{
		{"alert", 95, config.ResourceFields{Warning: 60, Alert: 90}, "alert limit"},
		{"warning", 70, config.ResourceFields{Warning: 60, Alert: 90}, "warning limit"},
		{"below", 50, config.ResourceFields{Warning: 60, Alert: 90}, ""},
		{"disabled", 100, config.ResourceFields{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			syncGoRun(t)
			buf := captureLog(t)

			origList := listProcesses
			listProcesses = func(context.Context) ([]*process.Process, error) { return nil, nil }
			t.Cleanup(func() { listProcesses = origList })

			mh := newHub(t, config.New(), nil)
			mh.checkLimits("cpu usage", tt.value, "%", tt.limits, t.TempDir())

			if tt.wantLog == "" {
				if strings.Contains(buf.String(), "limit") {
					t.Errorf("logged %q, want nothing", buf.String())
				}
				return
			}
			if !strings.Contains(buf.String(), tt.wantLog) {
				t.Errorf("log = %q, want %q", buf.String(), tt.wantLog)
			}
		})
	}
}

func TestRunBaseMonitor(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		if err := newHub(t, config.New(), nil).RunBaseMonitor("test", &config.BaseFields{Mode: "disabled"}); err != nil {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("bad pattern", func(t *testing.T) {
		mh := newHub(t, config.New(), nil)
		if err := mh.RunBaseMonitor("test", &config.BaseFields{Mode: "logger", Pattern: "([", WindowSeconds: 3600}); !errors.Is(err, ErrCompileRegexp) {
			t.Fatalf("error = %v, want ErrCompileRegexp", err)
		}
	})

	t.Run("unknown engine", func(t *testing.T) {
		mh := newHub(t, config.New(), nil)
		bm := &config.BaseFields{Mode: "logger", Engine: "smoke", Pattern: `(?P<ip>\S+)`, WindowSeconds: 3600}
		if err := mh.RunBaseMonitor("test", bm); !errors.Is(err, ErrEngineNotFound) {
			t.Fatalf("error = %v, want ErrEngineNotFound", err)
		}
	})

	t.Run("logger alerts", func(t *testing.T) {
		stubStartSource(t, feedLines("from 5.6.7.8", "from 5.6.7.8"))
		mh := newHub(t, config.New(), nil)
		bm := &config.BaseFields{Mode: "logger", Engine: "syslog", Pattern: `from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})`, Tries: 2, WindowSeconds: 3600}
		if err := mh.RunBaseMonitor("test", bm); err != nil {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("whitelist skips", func(t *testing.T) {
		stubStartSource(t, feedLines("from 9.9.9.9"))
		cfg := config.New()
		cfg.IPWhiteList = []string{"9.9.9.9"}
		mh := newHub(t, cfg, nil)
		bm := &config.BaseFields{Mode: "logger", Engine: "syslog", Pattern: `from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})`, Tries: 1, WindowSeconds: 3600}
		if err := mh.RunBaseMonitor("test", bm); err != nil {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("blocker bans", func(t *testing.T) {
		syncGoRun(t)
		stubStartSource(t, feedLines("from 5.6.7.8", "from 5.6.7.8"))
		ctrl := gomock.NewController(t)
		bp := mocks.NewMockBanPool(ctrl)
		bp.EXPECT().BanIP(gomock.Any(), "5.6.7.8", uint64(60)).Return(nil)

		mh := newHub(t, config.New(), bp)
		bm := &config.BaseFields{Mode: "blocker", Engine: "syslog", Pattern: `from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})`, Tries: 2, WindowSeconds: 3600, BanSeconds: 60}
		if err := mh.RunBaseMonitor("test", bm); err != nil {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("blocker ban error", func(t *testing.T) {
		syncGoRun(t)
		captureLog(t)
		stubStartSource(t, feedLines("from 5.6.7.8", "from 5.6.7.8"))
		ctrl := gomock.NewController(t)
		bp := mocks.NewMockBanPool(ctrl)
		bp.EXPECT().BanIP(gomock.Any(), "5.6.7.8", uint64(60)).Return(errors.New("boom"))

		mh := newHub(t, config.New(), bp)
		bm := &config.BaseFields{Mode: "blocker", Engine: "syslog", Pattern: `from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})`, Tries: 2, WindowSeconds: 3600, BanSeconds: 60}
		if err := mh.RunBaseMonitor("test", bm); err != nil {
			t.Fatalf("error = %v", err)
		}
	})
}

func goodMetrics(t *testing.T, cpuVal float64) {
	t.Helper()
	oNet, oDisk, oCPU, oMem := netIOCounters, diskIOCounters, cpuPercent, memVirtual
	netIOCounters = func(context.Context, bool) ([]net.IOCountersStat, error) {
		return []net.IOCountersStat{{BytesRecv: 10, BytesSent: 10}}, nil
	}
	diskIOCounters = func(context.Context, ...string) (map[string]disk.IOCountersStat, error) {
		return map[string]disk.IOCountersStat{"sda": {ReadCount: 1, WriteCount: 1}}, nil
	}
	cpuPercent = func(context.Context, time.Duration, bool) ([]float64, error) { return []float64{cpuVal}, nil }
	memVirtual = func(context.Context) (*mem.VirtualMemoryStat, error) {
		return &mem.VirtualMemoryStat{UsedPercent: 40}, nil
	}
	t.Cleanup(func() { netIOCounters, diskIOCounters, cpuPercent, memVirtual = oNet, oDisk, oCPU, oMem })
}

func TestCheckResourceMetrics(t *testing.T) {
	rm := &config.ResourceMonitorConfig{Enabled: true, CpuUsagePersentage: config.ResourceFields{Warning: 60}}

	t.Run("success", func(t *testing.T) {
		goodMetrics(t, 75)
		if err := newHub(t, config.New(), nil).checkResourceMetrics(rm); err != nil {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("net error", func(t *testing.T) {
		goodMetrics(t, 10)
		netIOCounters = func(context.Context, bool) ([]net.IOCountersStat, error) { return nil, errors.New("boom") }
		if err := newHub(t, config.New(), nil).checkResourceMetrics(rm); !errors.Is(err, ErrCantGetTrafficUsage) {
			t.Fatalf("error = %v, want ErrCantGetTrafficUsage", err)
		}
	})

	t.Run("disk error", func(t *testing.T) {
		goodMetrics(t, 10)
		diskIOCounters = func(context.Context, ...string) (map[string]disk.IOCountersStat, error) {
			return nil, errors.New("boom")
		}
		if err := newHub(t, config.New(), nil).checkResourceMetrics(rm); !errors.Is(err, ErrCantGetDiskUsage) {
			t.Fatalf("error = %v, want ErrCantGetDiskUsage", err)
		}
	})

	t.Run("cpu error", func(t *testing.T) {
		goodMetrics(t, 10)
		cpuPercent = func(context.Context, time.Duration, bool) ([]float64, error) { return nil, errors.New("boom") }
		if err := newHub(t, config.New(), nil).checkResourceMetrics(rm); !errors.Is(err, ErrCantGetCPUUsage) {
			t.Fatalf("error = %v, want ErrCantGetCPUUsage", err)
		}
	})

	t.Run("net after error", func(t *testing.T) {
		goodMetrics(t, 10)
		calls := 0
		netIOCounters = func(context.Context, bool) ([]net.IOCountersStat, error) {
			calls++
			if calls == 2 {
				return nil, errors.New("boom")
			}
			return []net.IOCountersStat{{}}, nil
		}
		if err := newHub(t, config.New(), nil).checkResourceMetrics(rm); !errors.Is(err, ErrCantGetTrafficUsage) {
			t.Fatalf("error = %v, want ErrCantGetTrafficUsage", err)
		}
	})

	t.Run("disk after error", func(t *testing.T) {
		goodMetrics(t, 10)
		calls := 0
		diskIOCounters = func(context.Context, ...string) (map[string]disk.IOCountersStat, error) {
			calls++
			if calls == 2 {
				return nil, errors.New("boom")
			}
			return map[string]disk.IOCountersStat{}, nil
		}
		if err := newHub(t, config.New(), nil).checkResourceMetrics(rm); !errors.Is(err, ErrCantGetDiskUsage) {
			t.Fatalf("error = %v, want ErrCantGetDiskUsage", err)
		}
	})

	t.Run("mem error", func(t *testing.T) {
		goodMetrics(t, 10)
		memVirtual = func(context.Context) (*mem.VirtualMemoryStat, error) { return nil, errors.New("boom") }
		if err := newHub(t, config.New(), nil).checkResourceMetrics(rm); !errors.Is(err, ErrCantGetRAMUsage) {
			t.Fatalf("error = %v, want ErrCantGetRAMUsage", err)
		}
	})

	t.Run("no cpu samples", func(t *testing.T) {
		goodMetrics(t, 10)
		cpuPercent = func(context.Context, time.Duration, bool) ([]float64, error) { return []float64{}, nil }
		if err := newHub(t, config.New(), nil).checkResourceMetrics(rm); !errors.Is(err, ErrCantGetCPUUsage) {
			t.Fatalf("error = %v, want ErrCantGetCPUUsage", err)
		}
	})
}

func TestCheckLimitsAlertSnapshotError(t *testing.T) {
	syncGoRun(t)
	captureLog(t)

	orig := listProcesses
	listProcesses = func(context.Context) ([]*process.Process, error) { return nil, nil }
	t.Cleanup(func() { listProcesses = orig })

	blocker := filepath.Join(t.TempDir(), "file")
	os.WriteFile(blocker, []byte("x"), 0644)

	mh := newHub(t, config.New(), nil)
	mh.checkLimits("cpu usage", 95, "%", config.ResourceFields{Alert: 90}, filepath.Join(blocker, "sub"))
}

func TestRunResourceMonitor(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		if err := newHub(t, config.New(), nil).RunResourceMonitor(&config.ResourceMonitorConfig{}); err != nil {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("loop", func(t *testing.T) {
		goodMetrics(t, 10)
		orig := resourcePollInterval
		resourcePollInterval = 5 * time.Millisecond
		t.Cleanup(func() { resourcePollInterval = orig })

		mh := newHub(t, config.New(), nil)
		rm := &config.ResourceMonitorConfig{Enabled: true, CpuUsagePersentage: config.ResourceFields{Warning: 5}}

		done := make(chan error, 1)
		go func() { done <- mh.RunResourceMonitor(rm) }()
		time.Sleep(20 * time.Millisecond)
		mh.cancel()

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("did not return after cancel")
		}
	})

	t.Run("loop with metric error", func(t *testing.T) {
		goodMetrics(t, 10)
		netIOCounters = func(context.Context, bool) ([]net.IOCountersStat, error) { return nil, errors.New("boom") }
		captureLog(t)
		orig := resourcePollInterval
		resourcePollInterval = 5 * time.Millisecond
		t.Cleanup(func() { resourcePollInterval = orig })

		mh := newHub(t, config.New(), nil)
		done := make(chan error, 1)
		go func() { done <- mh.RunResourceMonitor(&config.ResourceMonitorConfig{Enabled: true}) }()
		time.Sleep(20 * time.Millisecond)
		mh.cancel()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("did not return")
		}
	})
}

func TestRunMonitoringWithBaseError(t *testing.T) {
	stubStartSource(t, func(ctx context.Context, bm *config.BaseFields, out chan<- string) error {
		close(out)
		return nil
	})
	captureLog(t)

	ctrl := gomock.NewController(t)
	bp := mocks.NewMockBanPool(ctrl)
	bp.EXPECT().RestoreBans(gomock.Any()).Return(nil)

	cfg := config.New()
	cfg.SSHMonitor.Mode = "logger"
	cfg.SSHMonitor.Pattern = "(["
	cfg.WebBruteMonitor.Mode = "disabled"
	cfg.WebReconMonitor.Mode = "disabled"
	cfg.DatabaseMonitor.Mode = "disabled"
	cfg.ResourceMonitor.Enabled = false

	mh := newHub(t, cfg, bp)
	done := make(chan struct{})
	go func() {
		mh.RunMonitoring()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunMonitoring did not return")
	}
}

func TestRunMonitoring(t *testing.T) {
	stubStartSource(t, func(ctx context.Context, bm *config.BaseFields, out chan<- string) error {
		close(out)
		return nil
	})
	captureLog(t)

	ctrl := gomock.NewController(t)
	bp := mocks.NewMockBanPool(ctrl)
	bp.EXPECT().RestoreBans(gomock.Any()).Return(errors.New("boom"))

	cfg := config.New()
	cfg.SSHMonitor.Mode = "disabled"
	cfg.WebBruteMonitor.Mode = "disabled"
	cfg.WebReconMonitor.Mode = "disabled"
	cfg.DatabaseMonitor.Mode = "disabled"
	cfg.ResourceMonitor.Enabled = false

	mh := newHub(t, cfg, bp)
	done := make(chan struct{})
	go func() {
		mh.RunMonitoring()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunMonitoring did not return")
	}
}

func TestSaveSnapshot(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		dir := t.TempDir()
		if err := newHub(t, config.New(), nil).saveSnapshot(dir); err != nil {
			t.Fatalf("error = %v", err)
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 1 {
			t.Fatalf("wrote %d files, want 1", len(entries))
		}
	})

	t.Run("empty processes", func(t *testing.T) {
		orig := listProcesses
		listProcesses = func(context.Context) ([]*process.Process, error) { return nil, nil }
		t.Cleanup(func() { listProcesses = orig })
		if err := newHub(t, config.New(), nil).saveSnapshot(t.TempDir()); err != nil {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("list error", func(t *testing.T) {
		orig := listProcesses
		listProcesses = func(context.Context) ([]*process.Process, error) { return nil, errors.New("boom") }
		t.Cleanup(func() { listProcesses = orig })
		if err := newHub(t, config.New(), nil).saveSnapshot(t.TempDir()); !errors.Is(err, ErrCantGetProcesses) {
			t.Fatalf("error = %v, want ErrCantGetProcesses", err)
		}
	})

	t.Run("mkdir error", func(t *testing.T) {
		orig := listProcesses
		listProcesses = func(context.Context) ([]*process.Process, error) { return nil, nil }
		t.Cleanup(func() { listProcesses = orig })
		blocker := filepath.Join(t.TempDir(), "file")
		os.WriteFile(blocker, []byte("x"), 0644)
		if err := newHub(t, config.New(), nil).saveSnapshot(filepath.Join(blocker, "sub")); !errors.Is(err, ErrCantCreateSnapshotDir) {
			t.Fatalf("error = %v, want ErrCantCreateSnapshotDir", err)
		}
	})
}

func TestWriteSnapshotFlushError(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "snap")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	usages := []processUsage{{pid: 1, user: "root", command: "init"}}
	if err := writeSnapshot(f, usages); err == nil {
		t.Fatal("writeSnapshot() error = nil, want a flush failure on the closed file")
	}
}

func TestRunSourceRetriesThenStops(t *testing.T) {
	orig := sourceRetryInterval
	sourceRetryInterval = time.Millisecond
	t.Cleanup(func() { sourceRetryInterval = orig })
	captureLog(t)

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan string)
	go func() {
		for range ch {
		}
	}()

	calls := 0
	runSource(ctx, "test", ch, func(context.Context, chan<- string) error {
		calls++
		if calls >= 2 {
			cancel()
		}
		return errors.New("boom")
	})
	if calls < 2 {
		t.Fatalf("attach called %d times, want >= 2", calls)
	}
}

func TestOpenLogFile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "log")
		os.WriteFile(path, []byte("x"), 0644)
		f, err := openLogFile(context.Background(), path)
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		f.Close()
	})

	t.Run("retries then fails", func(t *testing.T) {
		oR, oI := openLogFileRetries, openLogFileRetryInterval
		openLogFileRetries, openLogFileRetryInterval = 2, time.Millisecond
		t.Cleanup(func() { openLogFileRetries, openLogFileRetryInterval = oR, oI })
		if _, err := openLogFile(context.Background(), "/no/such/file"); !errors.Is(err, ErrCantOpenLogFile) {
			t.Fatalf("error = %v, want ErrCantOpenLogFile", err)
		}
	})

	t.Run("context cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := openLogFile(ctx, "/no/such/file"); !errors.Is(err, ErrCantOpenLogFile) {
			t.Fatalf("error = %v, want ErrCantOpenLogFile", err)
		}
	})
}

func TestConnectToSyslog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	os.WriteFile(path, []byte(""), 0644)

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan string, 100)
	done := make(chan struct{})
	go func() {
		connectToSyslog(ctx, path, ch)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	f.WriteString("offender 1.2.3.4\n")
	f.Close()

	select {
	case <-ch:
	case <-time.After(time.Second):
	}

	cancel()
	go func() {
		for range ch {
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("connectToSyslog did not stop")
	}
}

func TestAttachToJournalNoBinary(t *testing.T) {
	t.Setenv("PATH", "")
	ch := make(chan string, 1)
	if err := attachToJournal(context.Background(), "sshd", ch); !errors.Is(err, ErrCantConnectToJournal) {
		t.Fatalf("error = %v, want ErrCantConnectToJournal", err)
	}
}
