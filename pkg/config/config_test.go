package config

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want RunConfig
	}{
		{"install short", []string{"open-defender", "-i"}, RunConfig{Install: true}},
		{"install long", []string{"open-defender", "--install"}, RunConfig{Install: true}},
		{"update short", []string{"open-defender", "-u"}, RunConfig{Update: true}},
		{"update long", []string{"open-defender", "--update"}, RunConfig{Update: true}},
		{"test short", []string{"open-defender", "-t"}, RunConfig{Test: true}},
		{"test long", []string{"open-defender", "--test"}, RunConfig{Test: true}},
		{"status short", []string{"open-defender", "-s"}, RunConfig{Status: true}},
		{"status long", []string{"open-defender", "--status"}, RunConfig{Status: true}},
		{"restart short", []string{"open-defender", "-r"}, RunConfig{Restart: true}},
		{"restart long", []string{"open-defender", "--restart"}, RunConfig{Restart: true}},
		{"help short", []string{"open-defender", "-h"}, RunConfig{Help: true}},
		{"help long", []string{"open-defender", "--help"}, RunConfig{Help: true}},
		{"none", []string{"open-defender"}, RunConfig{}},
		{"multiple", []string{"open-defender", "-i", "-r"}, RunConfig{Install: true, Restart: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseArgs(tt.argv)
			if err != nil {
				t.Fatalf("ParseArgs() error: %v", err)
			}
			if *got != tt.want {
				t.Errorf("ParseArgs() = %+v, want %+v", *got, tt.want)
			}
		})
	}
}

func TestParseArgsUnknown(t *testing.T) {
	if _, err := ParseArgs([]string{"open-defender", "--nope"}); !errors.Is(err, ErrUnknownArgument) {
		t.Fatalf("ParseArgs() error = %v, want ErrUnknownArgument", err)
	}
}

func disabledConfig() *Config {
	c := New()
	c.SSHMonitor.Mode = "disabled"
	c.WebReconMonitor.Mode = "disabled"
	c.WebBruteMonitor.Mode = "disabled"
	c.DatabaseMonitor.Mode = "disabled"
	c.ResourceMonitor.Enabled = false
	return c
}

func has(problems []error, target error) bool {
	for _, problem := range problems {
		if errors.Is(problem, target) {
			return true
		}
	}
	return false
}

func TestValidateValid(t *testing.T) {
	if problems := disabledConfig().Validate(); len(problems) != 0 {
		t.Fatalf("Validate() = %v, want none", problems)
	}
}

func TestValidateProblems(t *testing.T) {
	existing := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(existing, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mangle func(*Config)
		want   error
	}{
		{"empty database", func(c *Config) { c.BlockedIPsDatabase = "  " }, ErrEmptyValue},
		{"bad whitelist ip", func(c *Config) { c.IPWhiteList = []string{"nope"} }, ErrInvalidIP},
		{"bad mode", func(c *Config) { c.SSHMonitor.Mode = "banana" }, ErrInvalidValue},
		{"bad engine", func(c *Config) { c.SSHMonitor.Mode = "logger"; c.SSHMonitor.Engine = "smoke" }, ErrInvalidValue},
		{"syslog empty path", func(c *Config) {
			c.SSHMonitor.Mode = "logger"
			c.SSHMonitor.Engine = "syslog"
			c.SSHMonitor.LogPath = " "
		}, ErrEmptyValue},
		{"syslog missing file", func(c *Config) {
			c.SSHMonitor.Mode = "logger"
			c.SSHMonitor.Engine = "syslog"
			c.SSHMonitor.LogPath = "/no/such/log"
		}, ErrLogFileNotReadable},
		{"docker empty unit", func(c *Config) {
			c.SSHMonitor.Mode = "logger"
			c.SSHMonitor.Engine = "docker"
			c.SSHMonitor.UnitName = " "
		}, ErrEmptyValue},
		{"empty pattern", func(c *Config) {
			c.SSHMonitor.Mode = "logger"
			c.SSHMonitor.Engine = "journal"
			c.SSHMonitor.UnitName = "u"
			c.SSHMonitor.Pattern = " "
		}, ErrEmptyValue},
		{"bad pattern", func(c *Config) {
			c.SSHMonitor.Mode = "logger"
			c.SSHMonitor.Engine = "journal"
			c.SSHMonitor.UnitName = "u"
			c.SSHMonitor.Pattern = "(["
		}, ErrInvalidPattern},
		{"no ip group", func(c *Config) {
			c.SSHMonitor.Mode = "logger"
			c.SSHMonitor.Engine = "syslog"
			c.SSHMonitor.LogPath = existing
			c.SSHMonitor.Pattern = `x`
		}, ErrMissingIPGroup},
		{"zero tries", func(c *Config) {
			c.SSHMonitor.Mode = "logger"
			c.SSHMonitor.Engine = "journal"
			c.SSHMonitor.UnitName = "u"
			c.SSHMonitor.Pattern = `(?P<ip>\S+)`
			c.SSHMonitor.Tries = 0
			c.SSHMonitor.WindowSeconds = 0
		}, ErrZeroValue},
		{"blocker no ban", func(c *Config) {
			c.SSHMonitor.Mode = "blocker"
			c.SSHMonitor.Engine = "journal"
			c.SSHMonitor.UnitName = "u"
			c.SSHMonitor.BanSeconds = 0
		}, ErrZeroValue},
		{"resource empty dir", func(c *Config) {
			c.ResourceMonitor.Enabled = true
			c.ResourceMonitor.OutputTopSnapshotDir = " "
			c.ResourceMonitor.CpuUsagePersentage = ResourceFields{Warning: 1, Alert: 2}
		}, ErrEmptyValue},
		{"resource warn above alert", func(c *Config) {
			c.ResourceMonitor.Enabled = true
			c.ResourceMonitor.CpuUsagePersentage = ResourceFields{Warning: 90, Alert: 10}
		}, ErrWarningAboveAlert},
		{"resource no limits", func(c *Config) {
			c.ResourceMonitor.Enabled = true
			c.ResourceMonitor.CpuUsagePersentage = ResourceFields{}
			c.ResourceMonitor.RamUsagePersentage = ResourceFields{}
			c.ResourceMonitor.TrafficUsageMBs = ResourceFields{}
			c.ResourceMonitor.DiskUsageIOps = ResourceFields{}
		}, ErrNoLimitsSet},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := disabledConfig()
			tt.mangle(c)
			if !has(c.Validate(), tt.want) {
				t.Fatalf("Validate() did not report %v", tt.want)
			}
		})
	}
}

func TestMonitorsAndFields(t *testing.T) {
	monitors := New().Monitors()
	if len(monitors) != 4 {
		t.Fatalf("Monitors() = %d entries, want 4", len(monitors))
	}
	for _, m := range monitors {
		if m.Fields == nil {
			t.Errorf("monitor %q has nil fields", m.Name)
		}
	}

	if (&BaseFields{Mode: "disabled"}).Enabled() {
		t.Error("disabled reported as enabled")
	}
	if !(&BaseFields{Mode: "logger"}).Enabled() {
		t.Error("logger reported as disabled")
	}

	if got := (&BaseFields{Engine: "syslog", LogPath: "/l", UnitName: "u"}).Source(); got != "/l" {
		t.Errorf("Source() = %q, want /l", got)
	}
	if got := (&BaseFields{Engine: "journal", LogPath: "/l", UnitName: "u"}).Source(); got != "u" {
		t.Errorf("Source() = %q, want u", got)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.yaml")

	original := New()
	original.BlockedIPsDatabase = "/tmp/rt.db"
	original.IPWhiteList = []string{"10.0.0.1"}
	if err := original.SaveConfig(path); err != nil {
		t.Fatalf("SaveConfig() error: %v", err)
	}

	loaded := &Config{}
	if err := loaded.LoadConfigReadOnly(path); err != nil {
		t.Fatalf("LoadConfigReadOnly() error: %v", err)
	}
	if loaded.BlockedIPsDatabase != "/tmp/rt.db" || len(loaded.IPWhiteList) != 1 {
		t.Errorf("round trip lost data: %+v", loaded)
	}
}

func TestLoadConfigReadOnlyErrors(t *testing.T) {
	if err := (&Config{}).LoadConfigReadOnly(filepath.Join(t.TempDir(), "absent.yaml")); !errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("missing: error = %v, want ErrConfigNotFound", err)
	}

	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := (&Config{}).LoadConfigReadOnly(filepath.Join(blocker, "config.yaml")); !errors.Is(err, ErrStatConfig) {
		t.Fatalf("stat: error = %v, want ErrStatConfig", err)
	}

	dir := t.TempDir()
	if err := (&Config{}).LoadConfigReadOnly(dir); !errors.Is(err, ErrReadConfig) {
		t.Fatalf("read: error = %v, want ErrReadConfig", err)
	}

	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("- a\n- b"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := (&Config{}).LoadConfigReadOnly(bad); !errors.Is(err, ErrParseConfig) {
		t.Fatalf("parse: error = %v, want ErrParseConfig", err)
	}
}

func TestLoadConfigFirstRunAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "config.yaml")

	c := New()
	if err := c.LoadConfig(path); err != nil {
		t.Fatalf("LoadConfig() first run error: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("LoadConfig() did not create the file: %v", err)
	}
	if len(c.IPWhiteList) == 0 {
		t.Error("first run did not seed the whitelist")
	}

	if err := New().LoadConfig(path); err != nil {
		t.Fatalf("LoadConfig() reload error: %v", err)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	t.Run("get local ips fails", func(t *testing.T) {
		stubInterfaceAddrs(t, func() ([]net.Addr, error) { return nil, errors.New("boom") })
		if err := New().LoadConfig(filepath.Join(t.TempDir(), "config.yaml")); !errors.Is(err, ErrGettingNetworkInterfaces) {
			t.Fatalf("error = %v, want ErrGettingNetworkInterfaces", err)
		}
	})

	t.Run("first run save fails", func(t *testing.T) {
		stubMarshalYAML(t, func(any) ([]byte, error) { return nil, errors.New("boom") })
		if err := New().LoadConfig(filepath.Join(t.TempDir(), "config.yaml")); !errors.Is(err, ErrMarshalConfig) {
			t.Fatalf("error = %v, want ErrMarshalConfig", err)
		}
	})

	t.Run("stat fails", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := New().LoadConfig(filepath.Join(blocker, "config.yaml")); !errors.Is(err, ErrStatConfig) {
			t.Fatalf("error = %v, want ErrStatConfig", err)
		}
	})

	t.Run("read fails", func(t *testing.T) {
		if err := New().LoadConfig(t.TempDir()); !errors.Is(err, ErrReadConfig) {
			t.Fatalf("error = %v, want ErrReadConfig", err)
		}
	})

	t.Run("parse fails", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.yaml")
		if err := os.WriteFile(bad, []byte("- a\n- b"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := New().LoadConfig(bad); !errors.Is(err, ErrParseConfig) {
			t.Fatalf("error = %v, want ErrParseConfig", err)
		}
	})

	t.Run("final save fails", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := New().SaveConfig(path); err != nil {
			t.Fatal(err)
		}
		stubMarshalYAML(t, func(any) ([]byte, error) { return nil, errors.New("boom") })
		if err := New().LoadConfig(path); !errors.Is(err, ErrMarshalConfig) {
			t.Fatalf("error = %v, want ErrMarshalConfig", err)
		}
	})
}

func TestSaveConfigErrors(t *testing.T) {
	t.Run("mkdir fails", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := New().SaveConfig(filepath.Join(blocker, "sub", "config.yaml")); !errors.Is(err, ErrCreateConfigDir) {
			t.Fatalf("error = %v, want ErrCreateConfigDir", err)
		}
	})

	t.Run("encode fails", func(t *testing.T) {
		stubEncodeNode(t, func(*yaml.Node, any) error { return errors.New("boom") })
		if err := New().SaveConfig(filepath.Join(t.TempDir(), "config.yaml")); !errors.Is(err, ErrMarshalConfig) {
			t.Fatalf("error = %v, want ErrMarshalConfig", err)
		}
	})

	t.Run("marshal fails", func(t *testing.T) {
		stubMarshalYAML(t, func(any) ([]byte, error) { return nil, errors.New("boom") })
		if err := New().SaveConfig(filepath.Join(t.TempDir(), "config.yaml")); !errors.Is(err, ErrMarshalConfig) {
			t.Fatalf("error = %v, want ErrMarshalConfig", err)
		}
	})

	t.Run("write fails", func(t *testing.T) {
		if err := New().SaveConfig(t.TempDir()); !errors.Is(err, ErrWriteConfig) {
			t.Fatalf("error = %v, want ErrWriteConfig", err)
		}
	})
}

func TestGetLocalIps(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		stubInterfaceAddrs(t, func() ([]net.Addr, error) { return nil, errors.New("boom") })
		if _, err := New().GetLocalIps(); !errors.Is(err, ErrGettingNetworkInterfaces) {
			t.Fatalf("error = %v, want ErrGettingNetworkInterfaces", err)
		}
	})

	t.Run("mixed addr types", func(t *testing.T) {
		stubInterfaceAddrs(t, func() ([]net.Addr, error) {
			return []net.Addr{
				&net.IPNet{IP: net.IPv4(1, 2, 3, 4)},
				&net.IPAddr{IP: net.IPv4(5, 6, 7, 8)},
				&net.UnixAddr{Name: "x", Net: "unix"},
			}, nil
		})
		ips, err := New().GetLocalIps()
		if err != nil {
			t.Fatal(err)
		}
		if len(ips) != 2 {
			t.Fatalf("GetLocalIps() = %v, want two ip addresses", ips)
		}
	})
}

func TestApplyCommentsHelpers(t *testing.T) {
	c := New()

	c.applyComments(&yaml.Node{Kind: yaml.ScalarNode}, reflect.TypeOf(*c))

	type inner struct {
		X string `yaml:"x"`
	}
	type sample struct {
		Bare    string
		Skip    string `yaml:"-"`
		Missing string `yaml:"missing"`
		Present string `yaml:"present" comment:"hi"`
		Inner   inner  `yaml:",inline"`
	}

	node := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Value: "present"},
		{Kind: yaml.ScalarNode, Value: "v"},
	}}

	c.applyComments(node, reflect.TypeOf(sample{}))

	if node.Content[0].HeadComment != "hi" {
		t.Errorf("comment = %q, want hi", node.Content[0].HeadComment)
	}
}

func stubInterfaceAddrs(t *testing.T, fn func() ([]net.Addr, error)) {
	t.Helper()
	original := interfaceAddrs
	interfaceAddrs = fn
	t.Cleanup(func() { interfaceAddrs = original })
}

func stubEncodeNode(t *testing.T, fn func(*yaml.Node, any) error) {
	t.Helper()
	original := encodeNode
	encodeNode = fn
	t.Cleanup(func() { encodeNode = original })
}

func stubMarshalYAML(t *testing.T, fn func(any) ([]byte, error)) {
	t.Helper()
	original := marshalYAML
	marshalYAML = fn
	t.Cleanup(func() { marshalYAML = original })
}
