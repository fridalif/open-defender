package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

const commentTag = "comment"

type BaseFields struct {
	Mode          string `yaml:"mode" comment:"disabled, logger, blocker"`
	Engine        string `yaml:"engine" comment:"syslog, journal, docker"`
	LogPath       string `yaml:"log_path" comment:"path to the log file, used by the syslog engine only"`
	UnitName      string `yaml:"unit_name" comment:"systemd unit or container name, used by the journal and docker engines"`
	Tries         uint64 `yaml:"tries" comment:"how many hits within the window get the ip banned"`
	WindowSeconds uint64 `yaml:"window_seconds" comment:"the hits are counted over this window, the counters are dropped afterwards"`
	BanSeconds    uint64 `yaml:"ban_seconds" comment:"how long the ip stays banned, the blocker mode only"`
	Pattern       string `yaml:"pattern" comment:"the line is a hit when it matches, the address is taken from the (?P<ip>...) group"`
}

type ResourceFields struct {
	Warning uint64 `yaml:"warning" comment:"logged as a warning once the usage reaches it, zero turns the check off"`
	Alert   uint64 `yaml:"alert" comment:"logged as an alert and saves a snapshot of the processes, zero turns the check off"`
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
	CpuUsagePersentage   ResourceFields `yaml:"cpu_usage_persentage" comment:"cpu usage of the whole machine, percents"`
	RamUsagePersentage   ResourceFields `yaml:"ram_usage_persentage" comment:"ram usage of the whole machine, percents"`
	TrafficUsageMBs      ResourceFields `yaml:"traffic_usage_mbs" comment:"network traffic in and out, megabytes per second"`
	DiskUsageIOps        ResourceFields `yaml:"disk_usage_iops" comment:"disk reads and writes, operations per second"`
	OutputTopSnapshotDir string         `yaml:"output_top_snaphot_dir" comment:"the snapshots of the processes are written here, one <datetime>.sp file per alert"`
}

type Config struct {
	IPWhiteList        []string              `yaml:"ip_whitelist" comment:"these addresses are never banned, the addresses of the machine itself are put here on the first run"`
	BlockedIPsDatabase string                `yaml:"blocked_ips_database" comment:"the bans outlive a restart of the daemon, they are kept here"`
	SSHMonitor         SSHMonitorConfig      `yaml:"ssh_monitor" comment:"failed ssh logins"`
	WebReconMonitor    WebReconMonitorConfig `yaml:"web_recon_monitor" comment:"scanning of the web server for the paths that are not there"`
	WebBruteMonitor    WebBruteMonitorConfig `yaml:"web_brute_monitor" comment:"brute force of the login pages of the web server"`
	DatabaseMonitor    DatabaseMonitorConfig `yaml:"database_monitor" comment:"failed logins into the database"`
	ResourceMonitor    ResourceMonitorConfig `yaml:"resource_monitor" comment:"cpu, ram, traffic and disk of the machine, alerts only, nothing is ever banned by it"`
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
				Engine:        "journal",
				LogPath:       "/var/log/postgresql/postgresql-16-main.log",
				UnitName:      "postgresql",
				Tries:         5,
				WindowSeconds: 300,
				BanSeconds:    900,
				Pattern:       fmt.Sprintf(`host=(%s).*FATAL:\s+password authentication failed for user`, ipPattern),
			},
		},
		ResourceMonitor: ResourceMonitorConfig{
			Enabled: false,
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

type NamedMonitor struct {
	Name   string
	Fields *BaseFields
}

func (c *Config) Monitors() []NamedMonitor {
	return []NamedMonitor{
		{"ssh_monitor", &c.SSHMonitor.BaseFields},
		{"web_recon_monitor", &c.WebReconMonitor.BaseFields},
		{"web_brute_monitor", &c.WebBruteMonitor.BaseFields},
		{"database_monitor", &c.DatabaseMonitor.BaseFields},
	}
}

func (bm *BaseFields) Enabled() bool {
	return bm.Mode != modeDisabled
}

func (bm *BaseFields) Source() string {
	if bm.Engine == engineSyslog {
		return bm.LogPath
	}

	return bm.UnitName
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

	node := &yaml.Node{}
	if err := node.Encode(c); err != nil {
		return fmt.Errorf("config.SaveConfig() -> %w: %v", ErrMarshalConfig, err)
	}

	c.applyComments(node, reflect.TypeOf(*c))

	data, err := yaml.Marshal(node)
	if err != nil {
		return fmt.Errorf("config.SaveConfig() -> %w: %v", ErrMarshalConfig, err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("config.SaveConfig() -> %w: %v", ErrWriteConfig, err)
	}

	return nil
}

func (c *Config) applyComments(node *yaml.Node, structType reflect.Type) {
	if node.Kind != yaml.MappingNode || structType.Kind() != reflect.Struct {
		return
	}

	for i := range structType.NumField() {
		field := structType.Field(i)
		name, inline := c.yamlName(field)

		if inline {
			c.applyComments(node, field.Type)
			continue
		}

		if name == "" || name == "-" {
			continue
		}

		key, value := c.findKey(node, name)
		if key == nil {
			continue
		}

		if comment := field.Tag.Get(commentTag); comment != "" {
			key.HeadComment = comment
		}

		c.applyComments(value, field.Type)
	}
}

func (c *Config) yamlName(field reflect.StructField) (string, bool) {
	options := strings.Split(field.Tag.Get("yaml"), ",")

	inline := slices.Contains(options[1:], "inline")

	name := options[0]
	if name == "" && !inline {
		name = strings.ToLower(field.Name)
	}

	return name, inline
}

func (c *Config) findKey(node *yaml.Node, name string) (*yaml.Node, *yaml.Node) {
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == name {
			return node.Content[i], node.Content[i+1]
		}
	}

	return nil, nil
}

func (c *Config) LoadConfigReadOnly(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("config.LoadConfigReadOnly() -> %w: %s", ErrConfigNotFound, path)
	} else if err != nil {
		return fmt.Errorf("config.LoadConfigReadOnly() -> %w: %v", ErrStatConfig, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config.LoadConfigReadOnly() -> %w: %v", ErrReadConfig, err)
	}

	if err := yaml.Unmarshal(data, c); err != nil {
		return fmt.Errorf("config.LoadConfigReadOnly() -> %w: %v", ErrParseConfig, err)
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

	if err := c.SaveConfig(path); err != nil {
		return err
	}

	return nil
}
