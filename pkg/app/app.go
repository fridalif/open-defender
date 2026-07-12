package app

import (
	"fmt"
	"log"
	"open-defender/pkg/banpool"
	"open-defender/pkg/config"
	"open-defender/pkg/installer"
	"open-defender/pkg/monitor"
	"path"
)

type App interface {
	Initialize() error
	Install() error
	Run()
}

type app struct {
	cfg        *config.Config
	configPath string
	bp         banpool.BanPool
	installer  installer.Installer
}

func New() App {
	return &app{
		configPath: path.Join("/", "etc", "open-defender", "config.yaml"),
		cfg:        &config.Config{},
		installer:  installer.New(),
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
	return nil
}

func (a *app) Install() error {
	if err := a.installer.Install(); err != nil {
		return fmt.Errorf("app.Install() -> %w", err)
	}

	log.Printf("%s installed and started, check it with: systemctl status %s", a.installer.ServiceName(), a.installer.ServiceName())

	return nil
}

func (a *app) Run() {
	mh := monitor.New(a.cfg, a.bp)
	mh.RunMonitoring()
}
