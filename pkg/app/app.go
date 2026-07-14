package app

import (
	"fmt"
	"log"
	"open-defender/pkg/banpool"
	"open-defender/pkg/config"
	"open-defender/pkg/installer"
	"open-defender/pkg/monitor"
	"open-defender/pkg/updater"
	"os"
	"path"
	"strings"
	"text/tabwriter"
)

type App interface {
	Initialize() error
	Install() error
	Update() error
	TestConfig() error
	Status() error
	Restart() error
	Run()
}

type app struct {
	cfg        *config.Config
	configPath string
	bp         banpool.BanPool
	installer  installer.Installer
	updater    updater.Updater
}

func New() App {
	inst := installer.New()

	return &app{
		configPath: path.Join("/", "etc", "open-defender", "config.yaml"),
		cfg:        &config.Config{},
		installer:  inst,
		updater:    updater.New(inst),
	}
}

func (a *app) Initialize() error {
	cfg := config.New()
	err := cfg.LoadConfig(a.configPath)
	if err != nil {
		return fmt.Errorf("app.Initialize() -> %w", err)
	}
	a.cfg = cfg
	a.bp, err = banpool.New(cfg)
	if err != nil {
		return fmt.Errorf("app.Initialize() -> %w", err)
	}
	return nil
}

func (a *app) Install() error {
	if err := a.installer.Install(); err != nil {
		return fmt.Errorf("app.Install() -> %w", err)
	}

	log.Printf("%s installed and started, check it with: systemctl status %s", a.installer.ServiceName(), a.installer.ServiceName())

	return nil
}

func (a *app) Update() error {
	if err := a.updater.Update(); err != nil {
		return fmt.Errorf("app.Update() -> %w", err)
	}

	return nil
}

func (a *app) Restart() error {
	if err := a.installer.Restart(); err != nil {
		return fmt.Errorf("app.Restart() -> %w", err)
	}

	log.Printf("%s restarted, check it with: systemctl status %s", a.installer.ServiceName(), a.installer.ServiceName())

	return nil
}

func (a *app) TestConfig() error {
	cfg := config.New()

	if err := cfg.LoadConfigReadOnly(a.configPath); err != nil {
		return fmt.Errorf("app.TestConfig() -> %w", err)
	}

	problems := cfg.Validate()
	if len(problems) != 0 {
		for _, problem := range problems {
			log.Println(problem.Error())
		}

		return fmt.Errorf("app.TestConfig() -> %w: %s: %d problem(s)", config.ErrInvalidConfig, a.configPath, len(problems))
	}

	log.Printf("%s is valid", a.configPath)

	return nil
}

func (a *app) Status() error {
	cfg := config.New()

	if err := cfg.LoadConfigReadOnly(a.configPath); err != nil {
		return fmt.Errorf("app.Status() -> %w", err)
	}

	fmt.Printf("%s\n\n", a.configPath)

	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(writer, "MONITOR\tMODE\tENGINE\tSOURCE\tTRIES")

	var disabled []string

	for _, monitor := range cfg.Monitors() {
		if !monitor.Fields.Enabled() {
			disabled = append(disabled, monitor.Name)
			continue
		}

		tries := fmt.Sprintf("%d in %ds", monitor.Fields.Tries, monitor.Fields.WindowSeconds)
		if monitor.Fields.Mode == "blocker" {
			tries += fmt.Sprintf(", ban %ds", monitor.Fields.BanSeconds)
		}

		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", monitor.Name, monitor.Fields.Mode, monitor.Fields.Engine, monitor.Fields.Source(), tries)
	}

	if cfg.ResourceMonitor.Enabled {
		fmt.Fprintf(writer, "resource_monitor\tenabled\t-\t%s\t%s\n", cfg.ResourceMonitor.OutputTopSnapshotDir, a.resourceLimits(&cfg.ResourceMonitor))
	} else {
		disabled = append(disabled, "resource_monitor")
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("app.Status() -> %w: %v", ErrWriteStatus, err)
	}

	if len(disabled) != 0 {
		fmt.Printf("\ndisabled: %s\n", strings.Join(disabled, ", "))
	}

	return nil
}

func (a *app) resourceLimits(rm *config.ResourceMonitorConfig) string {
	limits := []struct {
		name   string
		fields config.ResourceFields
	}{
		{"cpu", rm.CpuUsagePersentage},
		{"ram", rm.RamUsagePersentage},
		{"traffic", rm.TrafficUsageMBs},
		{"disk", rm.DiskUsageIOps},
	}

	var set []string

	for _, limit := range limits {
		if limit.fields.Warning == 0 && limit.fields.Alert == 0 {
			continue
		}

		set = append(set, fmt.Sprintf("%s %d/%d", limit.name, limit.fields.Warning, limit.fields.Alert))
	}

	if len(set) == 0 {
		return "no limits"
	}

	return strings.Join(set, ", ")
}

func (a *app) Run() {
	mh := monitor.New(a.cfg, a.bp)
	mh.RunMonitoring()
}
