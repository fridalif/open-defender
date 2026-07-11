package app

import (
	"context"
	"fmt"
	"open-defender/pkg/config"
	"path"
)

type App interface {
	Initialize() error
	Run() error
}

type app struct {
	ctx        context.Context
	cancel     context.CancelFunc
	cfg        *config.Config
	configPath string
}

func New() App {
	ctx, cancel := context.WithCancel(context.Background())
	return &app{
		ctx:        ctx,
		cancel:     cancel,
		configPath: path.Join("/", "etc", "open-defender", "config.yaml"),
		cfg:        &config.Config{},
	}
}

func (a *app) Initialize() error {
	cfg := config.New()
	err := cfg.LoadConfig(a.configPath)
	if err != nil {
		return fmt.Errorf("app.Initialize() -> %w", err)
	}
	return nil
}

func (a *app) Run() error {
	return nil
}
