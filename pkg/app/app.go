package app

import (
	"fmt"
	"log"
	"open-defender/pkg/banpool"
	"open-defender/pkg/config"
	"open-defender/pkg/installer"
	"open-defender/pkg/monitor"
	"open-defender/pkg/updater"
	"path"
)

type App interface {
	Initialize() error
	Install() error
	Update() error
	TestConfig() error
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

func (a *app) Run() {
	mh := monitor.New(a.cfg, a.bp)
	mh.RunMonitoring()
}
