package app

import (
	"context"
	"fmt"
	"log"
	"open-defender/pkg/config"
	"open-defender/pkg/installer"
	"path"
)

type App interface {
	Initialize() error
	Install() error
	Run() error
}

type app struct {
	ctx        context.Context
	cancel     context.CancelFunc
	cfg        *config.Config
	configPath string
	installer  installer.Installer
}

func New() App {
	ctx, cancel := context.WithCancel(context.Background())
	return &app{
		ctx:        ctx,
		cancel:     cancel,
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
	return nil
}

func (a *app) Install() error {
	if err := a.installer.Install(); err != nil {
		return fmt.Errorf("app.Install() -> %w", err)
	}

	log.Printf("%s installed and started, check it with: systemctl status %s", a.installer.ServiceName(), a.installer.ServiceName())

	return nil
}

func (a *app) Run() error {
	return nil
}
