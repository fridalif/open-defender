package monitor

import (
	"context"
	"open-defender/pkg/config"
)

type MonitorHub interface {
	RunMonitoring()
	RunBaseMonitor(bm *config.BaseFields) error
	RunResourceMonitor(rm *config.ResourceFields) error
}

type monitorHub struct {
	cfg    *config.Config
	ctx    context.Context
	cancel context.CancelFunc
}

func New(cfg *config.Config) MonitorHub {
	ctx, cancel := context.WithCancel(context.Background())
	return &monitorHub{
		ctx:    ctx,
		cancel: cancel,
		cfg:    cfg,
	}
}

func (mh *monitorHub) RunMonitoring() {
	defer mh.cancel()

}

func (mh *monitorHub) RunBaseMonitor(bm *config.BaseFields) error {
	return nil
}

func (mh *monitorHub) RunResourceMonitor(rm *config.ResourceFields) error {
	return nil
}
