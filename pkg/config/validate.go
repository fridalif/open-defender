package config

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
)

const (
	modeDisabled = "disabled"
	modeBlocker  = "blocker"

	engineSyslog = "syslog"

	ipGroup = "ip"
)

var (
	validModes   = []string{modeDisabled, "logger", modeBlocker}
	validEngines = []string{engineSyslog, "journal", "docker"}
)

func (c *Config) Validate() []error {
	var problems []error

	if strings.TrimSpace(c.BlockedIPsDatabase) == "" {
		problems = append(problems, fmt.Errorf("blocked_ips_database: %w", ErrEmptyValue))
	}

	for _, ip := range c.IPWhiteList {
		if net.ParseIP(ip) == nil {
			problems = append(problems, fmt.Errorf("ip_whitelist: %w: %q", ErrInvalidIP, ip))
		}
	}

	for _, monitor := range c.Monitors() {
		problems = append(problems, c.validateBase(monitor.Name, monitor.Fields)...)
	}

	problems = append(problems, c.validateResource("resource_monitor", &c.ResourceMonitor)...)

	return problems
}

func (c *Config) validateBase(name string, bm *BaseFields) []error {
	if !slices.Contains(validModes, bm.Mode) {
		return []error{fmt.Errorf("%s.mode: %w: %q, expected one of: %s", name, ErrInvalidValue, bm.Mode, strings.Join(validModes, ", "))}
	}

	if bm.Mode == modeDisabled {
		return nil
	}

	var problems []error

	switch {
	case !slices.Contains(validEngines, bm.Engine):
		problems = append(problems, fmt.Errorf("%s.engine: %w: %q, expected one of: %s", name, ErrInvalidValue, bm.Engine, strings.Join(validEngines, ", ")))

	case bm.Engine == engineSyslog:
		if strings.TrimSpace(bm.LogPath) == "" {
			problems = append(problems, fmt.Errorf("%s.log_path: %w: the syslog engine reads it", name, ErrEmptyValue))
			break
		}

		if _, err := os.Stat(bm.LogPath); err != nil {
			problems = append(problems, fmt.Errorf("%s.log_path: %w: %s", name, ErrLogFileNotReadable, bm.LogPath))
		}

	default:
		if strings.TrimSpace(bm.UnitName) == "" {
			problems = append(problems, fmt.Errorf("%s.unit_name: %w: the %s engine reads it", name, ErrEmptyValue, bm.Engine))
		}
	}

	problems = append(problems, c.validatePattern(name, bm.Pattern)...)

	if bm.Tries == 0 {
		problems = append(problems, fmt.Errorf("%s.tries: %w: every address would be caught on its first hit", name, ErrZeroValue))
	}

	if bm.WindowSeconds == 0 {
		problems = append(problems, fmt.Errorf("%s.window_seconds: %w", name, ErrZeroValue))
	}

	if bm.Mode == modeBlocker && bm.BanSeconds == 0 {
		problems = append(problems, fmt.Errorf("%s.ban_seconds: %w: a ban of the blocker mode would be lifted at once", name, ErrZeroValue))
	}

	return problems
}

func (c *Config) validatePattern(name string, pattern string) []error {
	if strings.TrimSpace(pattern) == "" {
		return []error{fmt.Errorf("%s.pattern: %w", name, ErrEmptyValue)}
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return []error{fmt.Errorf("%s.pattern: %w: %v", name, ErrInvalidPattern, err)}
	}

	if !slices.Contains(re.SubexpNames(), ipGroup) {
		return []error{fmt.Errorf("%s.pattern: %w: the address is taken from a (?P<%s>...) group", name, ErrMissingIPGroup, ipGroup)}
	}

	return nil
}

func (c *Config) validateResource(name string, rm *ResourceMonitorConfig) []error {
	if !rm.Enabled {
		return nil
	}

	var problems []error

	if strings.TrimSpace(rm.OutputTopSnapshotDir) == "" {
		problems = append(problems, fmt.Errorf("%s.output_top_snaphot_dir: %w: the snapshots of an alert are written there", name, ErrEmptyValue))
	}

	limits := []struct {
		name   string
		fields ResourceFields
	}{
		{"cpu_usage_persentage", rm.CpuUsagePersentage},
		{"ram_usage_persentage", rm.RamUsagePersentage},
		{"traffic_usage_mbs", rm.TrafficUsageMBs},
		{"disk_usage_iops", rm.DiskUsageIOps},
	}

	set := false

	for _, limit := range limits {
		if limit.fields.Warning != 0 || limit.fields.Alert != 0 {
			set = true
		}

		if limit.fields.Warning != 0 && limit.fields.Alert != 0 && limit.fields.Warning > limit.fields.Alert {
			problems = append(problems, fmt.Errorf("%s.%s: %w: warning is %d, alert is %d", name, limit.name, ErrWarningAboveAlert, limit.fields.Warning, limit.fields.Alert))
		}
	}

	if !set {
		problems = append(problems, fmt.Errorf("%s: %w: it is enabled, yet every limit is zero", name, ErrNoLimitsSet))
	}

	return problems
}
