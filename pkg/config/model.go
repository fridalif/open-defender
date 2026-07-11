package config

import "fmt"

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
	BaseFields
}

type WebReconMonitorConfig struct {
	BaseFields
}

type WebBruteMonitorConfig struct {
	BaseFields
}

type DatabaseMonitorConfig struct {
	BaseFields
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
	SSHMonitor      SSHMonitorConfig      `yaml:"ssh_monitor"`
	WebReconMonitor WebReconMonitorConfig `yaml:"web_recon_monitor"`
	WebBruteMonitor WebBruteMonitorConfig `yaml:"web_brute_monitor"`
	DatabaseMonitor DatabaseMonitorConfig `yaml:"database_monitor"`
	ResourceMonitor ResourceMonitorConfig `yaml:"resource_monitor"`
}

const ipPattern = `?P<ip>(?:\d{1,3}\.){3}\d{1,3}`

func LoadConfig() *Config {
	config := &Config{
		SSHMonitor: SSHMonitorConfig{
			BaseFields: BaseFields{
				Mode:          "logger",
				Engine:        "syslog",
				LogPath:       "/var/log/auth.log",
				UnitName:      "",
				Tries:         5,
				WindowSeconds: 300,
				BanSeconds:    900,
				Pattern:       fmt.Sprintf(`Failed password for (?:invalid user )?\S+ from (%s)`, ipPattern),
			},
		},
		WebReconMonitor: WebReconMonitorConfig{},
		WebBruteMonitor: WebBruteMonitorConfig{},
		DatabaseMonitor: DatabaseMonitorConfig{},
		ResourceMonitor: ResourceMonitorConfig{},
	}
}
