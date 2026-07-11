package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type BaseFields struct {
	Mode          string `yaml:"mode"`      // disabled, logger, blocker
	Engine        string `yaml:"engine"`    // syslog, journal, docker
	LogPath       string `yaml:"log_path"`  // if engine equals syslog
	UnitName      string `yaml:"unit_name"` // systemd unit or container name (if engine not equal syslog)
	Tries         uint64 `yaml:"tries"`
	WindowSeconds uint64 `yaml:"window_seconds"`
	BanSeconds    uint64 `yaml:"ban_seconds"`
	Pattern       string `yaml:"pattern"`
}

type ResourceFields struct {
	Warning uint64 `yaml:"warning"`
	Alert   uint64 `yaml:"alert"`
}

type SSHMonitorConfig struct {
	BaseFields `yaml:",inline"`
}

type WebReconMonitorConfig struct {
	BaseFields `yaml:",inline"`
}

type WebBruteMonitorConfig struct {
	BaseFields `yaml:",inline"`
}

type DatabaseMonitorConfig struct {
	BaseFields `yaml:",inline"`
}

type ResourceMonitorConfig struct {
	Enabled              bool           `yaml:"enabled"`
	CpuUsagePersentage   ResourceFields `yaml:"cpu_usage_persentage"`
	RamUsagePersentage   ResourceFields `yaml:"ram_usage_persentage"`
	TrafficUsageMBs      ResourceFields `yaml:"traffic_usage_mbs"`
	DiskUsageIOps        ResourceFields `yaml:"disk_usage_iops"`
	OutputTopSnapshotDir string         `yaml:"output_top_snaphot_dir"`
}

type Config struct {
	IPWhiteList        []string              `yaml:"ip_whitelist"`
	BlockedIPsDatabase string                `yaml:"blocked_ips_database"`
	SSHMonitor         SSHMonitorConfig      `yaml:"ssh_monitor"`
	WebReconMonitor    WebReconMonitorConfig `yaml:"web_recon_monitor"`
	WebBruteMonitor    WebBruteMonitorConfig `yaml:"web_brute_monitor"`
	DatabaseMonitor    DatabaseMonitorConfig `yaml:"database_monitor"`
	ResourceMonitor    ResourceMonitorConfig `yaml:"resource_monitor"`
}

const ipPattern = `?P<ip>(?:\d{1,3}\.){3}\d{1,3}`

func New() *Config {
	config := &Config{
		BlockedIPsDatabase: "/var/open-defender/blocked.db",
		SSHMonitor: SSHMonitorConfig{
			BaseFields: BaseFields{
				Mode:          "logger",
				Engine:        "syslog",
				LogPath:       "/var/log/auth.log",
				UnitName:      "sshd",
				Tries:         5,
				WindowSeconds: 300,
				BanSeconds:    900,
				Pattern:       fmt.Sprintf(`Failed password for (?:invalid user )?\S+ from (%s)`, ipPattern),
			},
		},
		WebReconMonitor: WebReconMonitorConfig{
			BaseFields: BaseFields{
				Mode:          "disabled",
				Engine:        "syslog",
				LogPath:       "/var/log/nginx/access.log",
				UnitName:      "nginx",
				Tries:         10,
				WindowSeconds: 60,
				BanSeconds:    600,
				Pattern:       fmt.Sprintf(`(%s) - - \[.*?\] "(?:GET|POST|HEAD) \S+ HTTP/\d\.\d" 40[34]`, ipPattern),
			},
		},
		WebBruteMonitor: WebBruteMonitorConfig{
			BaseFields: BaseFields{
				Mode:          "disabled",
				Engine:        "syslog",
				LogPath:       "/var/log/nginx/access.log",
				UnitName:      "nginx",
				Tries:         5,
				WindowSeconds: 120,
				BanSeconds:    900,
				Pattern:       fmt.Sprintf(`(%s) - - \[.*?\] "POST (?:/login|/wp-login\.php|/admin) HTTP/\d\.\d" 40[13]`, ipPattern),
			},
		},
		DatabaseMonitor: DatabaseMonitorConfig{
			BaseFields: BaseFields{
				Mode:          "disabled",
				Engine:        "syslog",
				LogPath:       "/var/log/postgresql/postgresql.log",
				UnitName:      "postgresql",
				Tries:         5,
				WindowSeconds: 300,
				BanSeconds:    900,
				Pattern:       fmt.Sprintf(`host=(%s).*FATAL:\s+password authentication failed for user`, ipPattern),
			},
		},
		ResourceMonitor: ResourceMonitorConfig{
			Enabled: true,
			CpuUsagePersentage: ResourceFields{
				Warning: 60,
				Alert:   90,
			},
			RamUsagePersentage: ResourceFields{
				Warning: 60,
				Alert:   90,
			},
			TrafficUsageMBs: ResourceFields{
				Warning: 0,
				Alert:   0,
			},
			DiskUsageIOps: ResourceFields{
				Warning: 0,
				Alert:   0,
			},
			OutputTopSnapshotDir: "/var/log/open-defender/",
		},
	}
	return config
}

func (c *Config) GetLocalIps() ([]string, error) {
	var ips []string

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("config.GetLocalIps() -> %w: %v", ErrGettingNetworkInterfaces, err)
	}

	for _, addr := range addrs {
		var ip net.IP

		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}

		if ip == nil {
			continue
		}

		ips = append(ips, ip.String())
	}

	return ips, nil
}

func (c *Config) SaveConfig(path string) error {
	dir := filepath.Dir(path)

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("config.SaveConfig() -> %w: %v", ErrCreateConfigDir, err)
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("config.SaveConfig() -> %w: %v", ErrMarshalConfig, err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("config.SaveConfig() -> %w: %v", ErrWriteConfig, err)
	}

	return nil
}

func (c *Config) LoadConfig(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		ips, err := c.GetLocalIps()
		if err != nil {
			return fmt.Errorf("config.LoadConfig() -> %w", err)
		}
		c.IPWhiteList = ips

		if err := c.SaveConfig(path); err != nil {
			return err
		}
	} else if err != nil {
		return fmt.Errorf("config.LoadConfig() -> %w: %v", ErrStatConfig, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config.LoadConfig() -> %w: %v", ErrReadConfig, err)
	}

	if err := yaml.Unmarshal(data, c); err != nil {
		return fmt.Errorf("config.LoadConfig() -> %w: %v", ErrParseConfig, err)
	}

	// for easy update config after new program release
	if err := c.SaveConfig(path); err != nil {
		return err
	}

	return nil
}
