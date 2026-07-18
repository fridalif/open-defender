package app

import (
	"open-defender/pkg/config"
	"open-defender/pkg/installer"
	"open-defender/pkg/updater"
)

func NewAppForTest(cfg *config.Config, configPath string, inst installer.Installer, upd updater.Updater) App {
	return &app{
		cfg:        cfg,
		configPath: configPath,
		installer:  inst,
		updater:    upd,
	}
}
