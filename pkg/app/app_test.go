package app_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"open-defender/pkg/app"
	"open-defender/pkg/config"
	instmocks "open-defender/pkg/installer/mocks"
	updmocks "open-defender/pkg/updater/mocks"

	"go.uber.org/mock/gomock"
)

func disabledConfig() *config.Config {
	c := config.New()
	c.SSHMonitor.Mode = "disabled"
	c.WebReconMonitor.Mode = "disabled"
	c.WebBruteMonitor.Mode = "disabled"
	c.DatabaseMonitor.Mode = "disabled"
	c.ResourceMonitor.Enabled = false
	return c
}

func mocksFor(t *testing.T) (*instmocks.MockInstaller, *updmocks.MockUpdater) {
	ctrl := gomock.NewController(t)
	return instmocks.NewMockInstaller(ctrl), updmocks.NewMockUpdater(ctrl)
}

func writeConfig(t *testing.T, c *config.Config) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := c.SaveConfig(path); err != nil {
		t.Fatalf("saving config: %v", err)
	}
	return path
}

func TestNew(t *testing.T) {
	if app.New() == nil {
		t.Fatal("New() returned nil")
	}
}

func TestInstall(t *testing.T) {
	inst, upd := mocksFor(t)
	inst.EXPECT().Install().Return(nil)
	inst.EXPECT().ServiceName().Return("open-defender").AnyTimes()
	if err := app.NewAppForTest(disabledConfig(), "", inst, upd).Install(); err != nil {
		t.Fatalf("Install() error: %v", err)
	}
}

func TestInstallFailure(t *testing.T) {
	inst, upd := mocksFor(t)
	inst.EXPECT().Install().Return(errors.New("boom"))
	if err := app.NewAppForTest(disabledConfig(), "", inst, upd).Install(); err == nil {
		t.Fatal("Install() error = nil, want failure")
	}
}

func TestUpdate(t *testing.T) {
	inst, upd := mocksFor(t)
	upd.EXPECT().Update().Return(nil)
	if err := app.NewAppForTest(disabledConfig(), "", inst, upd).Update(); err != nil {
		t.Fatalf("Update() error: %v", err)
	}
}

func TestUpdateFailure(t *testing.T) {
	inst, upd := mocksFor(t)
	upd.EXPECT().Update().Return(errors.New("boom"))
	if err := app.NewAppForTest(disabledConfig(), "", inst, upd).Update(); err == nil {
		t.Fatal("Update() error = nil, want failure")
	}
}

func TestRestart(t *testing.T) {
	inst, upd := mocksFor(t)
	inst.EXPECT().Restart().Return(nil)
	inst.EXPECT().ServiceName().Return("open-defender").AnyTimes()
	if err := app.NewAppForTest(disabledConfig(), "", inst, upd).Restart(); err != nil {
		t.Fatalf("Restart() error: %v", err)
	}
}

func TestRestartFailure(t *testing.T) {
	inst, upd := mocksFor(t)
	inst.EXPECT().Restart().Return(errors.New("boom"))
	if err := app.NewAppForTest(disabledConfig(), "", inst, upd).Restart(); err == nil {
		t.Fatal("Restart() error = nil, want failure")
	}
}

func TestTestConfig(t *testing.T) {
	inst, upd := mocksFor(t)
	a := app.NewAppForTest(disabledConfig(), writeConfig(t, disabledConfig()), inst, upd)
	if err := a.TestConfig(); err != nil {
		t.Fatalf("TestConfig() error: %v", err)
	}
}

func TestTestConfigMissing(t *testing.T) {
	inst, upd := mocksFor(t)
	a := app.NewAppForTest(disabledConfig(), filepath.Join(t.TempDir(), "absent.yaml"), inst, upd)
	if err := a.TestConfig(); !errors.Is(err, config.ErrConfigNotFound) {
		t.Fatalf("TestConfig() error = %v, want ErrConfigNotFound", err)
	}
}

func TestTestConfigInvalid(t *testing.T) {
	inst, upd := mocksFor(t)
	c := disabledConfig()
	c.SSHMonitor.Mode = "bogus"
	a := app.NewAppForTest(disabledConfig(), writeConfig(t, c), inst, upd)
	if err := a.TestConfig(); !errors.Is(err, config.ErrInvalidConfig) {
		t.Fatalf("TestConfig() error = %v, want ErrInvalidConfig", err)
	}
}

func TestStatus(t *testing.T) {
	inst, upd := mocksFor(t)
	a := app.NewAppForTest(disabledConfig(), writeConfig(t, disabledConfig()), inst, upd)
	if err := a.Status(); err != nil {
		t.Fatalf("Status() error: %v", err)
	}
}

func TestStatusEBPFMonitors(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			inst, upd := mocksFor(t)
			c := disabledConfig()
			c.EbpfMonitors.NetworkAntirecon.Mode = "disabled"
			c.EbpfMonitors.UserCommandController.Mode = "disabled"
			if enabled {
				c.EbpfMonitors.NetworkAntirecon.Mode = "blocker"
				c.EbpfMonitors.NetworkAntirecon.PortsCount = 7
				c.EbpfMonitors.NetworkAntirecon.WindowSeconds = 30
				c.EbpfMonitors.NetworkAntirecon.BanSeconds = 60
				c.EbpfMonitors.UserCommandController.Mode = "logger"
			}
			a := app.NewAppForTest(disabledConfig(), writeConfig(t, c), inst, upd)
			output, err := os.CreateTemp(t.TempDir(), "status")
			if err != nil {
				t.Fatal(err)
			}
			original := os.Stdout
			os.Stdout = output
			err = a.Status()
			os.Stdout = original
			if err != nil {
				t.Fatal(err)
			}
			if err := output.Close(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(output.Name())
			if err != nil {
				t.Fatal(err)
			}
			status := string(data)
			if enabled {
				for _, want := range []string{"network_antirecon", "user_command_controller", "7 ports in 30s, ban 60s", "logger", "ebpf"} {
					if !strings.Contains(status, want) {
						t.Errorf("status missing %q: %s", want, status)
					}
				}
			} else if !strings.Contains(status, "network_antirecon, user_command_controller") {
				t.Errorf("disabled monitors missing: %s", status)
			}
		})
	}
}

func TestStatusMissing(t *testing.T) {
	inst, upd := mocksFor(t)
	a := app.NewAppForTest(disabledConfig(), filepath.Join(t.TempDir(), "absent.yaml"), inst, upd)
	if err := a.Status(); !errors.Is(err, config.ErrConfigNotFound) {
		t.Fatalf("Status() error = %v, want ErrConfigNotFound", err)
	}
}

func TestStatusWithLimits(t *testing.T) {
	inst, upd := mocksFor(t)
	c := config.New()
	c.SSHMonitor.Mode = "blocker"
	c.WebReconMonitor.Mode = "disabled"
	c.WebBruteMonitor.Mode = "disabled"
	c.DatabaseMonitor.Mode = "disabled"
	c.ResourceMonitor.Enabled = true
	c.ResourceMonitor.CpuUsagePersentage = config.ResourceFields{Warning: 60, Alert: 90}
	c.ResourceMonitor.RamUsagePersentage = config.ResourceFields{}
	c.ResourceMonitor.TrafficUsageMBs = config.ResourceFields{}
	c.ResourceMonitor.DiskUsageIOps = config.ResourceFields{}
	a := app.NewAppForTest(disabledConfig(), writeConfig(t, c), inst, upd)
	if err := a.Status(); err != nil {
		t.Fatalf("Status() error: %v", err)
	}
}

func TestStatusNoLimits(t *testing.T) {
	inst, upd := mocksFor(t)
	c := disabledConfig()
	c.ResourceMonitor.Enabled = true
	c.ResourceMonitor.CpuUsagePersentage = config.ResourceFields{}
	c.ResourceMonitor.RamUsagePersentage = config.ResourceFields{}
	c.ResourceMonitor.TrafficUsageMBs = config.ResourceFields{}
	c.ResourceMonitor.DiskUsageIOps = config.ResourceFields{}
	a := app.NewAppForTest(disabledConfig(), writeConfig(t, c), inst, upd)
	if err := a.Status(); err != nil {
		t.Fatalf("Status() error: %v", err)
	}
}

func TestInitializeAndRun(t *testing.T) {
	inst, upd := mocksFor(t)
	c := disabledConfig()
	c.BlockedIPsDatabase = filepath.Join(t.TempDir(), "blocked.db")

	a := app.NewAppForTest(nil, writeConfig(t, c), inst, upd)
	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() error: %v", err)
	}

	done := make(chan struct{})
	go func() {
		a.Run()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run() did not return")
	}
}

func TestInitializeConfigError(t *testing.T) {
	inst, upd := mocksFor(t)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	a := app.NewAppForTest(nil, filepath.Join(blocker, "config.yaml"), inst, upd)
	if err := a.Initialize(); err == nil {
		t.Fatal("Initialize() error = nil, want config failure")
	}
}

func TestInitializeInvalidNetworkAntireconConfig(t *testing.T) {
	inst, upd := mocksFor(t)
	c := disabledConfig()
	c.EbpfMonitors.NetworkAntirecon.Mode = "logger"
	c.EbpfMonitors.NetworkAntirecon.WindowSeconds = 0
	a := app.NewAppForTest(nil, writeConfig(t, c), inst, upd)
	if err := a.Initialize(); !errors.Is(err, config.ErrInvalidConfig) {
		t.Fatalf("Initialize() error = %v, want ErrInvalidConfig", err)
	}
}

func TestInitializeBanpoolError(t *testing.T) {
	inst, upd := mocksFor(t)
	c := disabledConfig()
	c.BlockedIPsDatabase = "/proc/nonexistent/blocked.db"
	a := app.NewAppForTest(nil, writeConfig(t, c), inst, upd)
	if err := a.Initialize(); err == nil {
		t.Fatal("Initialize() error = nil, want banpool failure")
	}
}
