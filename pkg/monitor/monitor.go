package monitor

import (
	"context"
	"open-defender/pkg/config"
	"sync"
)

type MonitorHub interface {
	RunMonitoring()
	RunBaseMonitor(bm *config.BaseFields) error
	RunResourceMonitor(rm *config.ResourceMonitorConfig) error
	Log(critLevel int, message string)
}

type monitorHub struct {
	cfg    *config.Config
	ctx    context.Context
	cancel context.CancelFunc
	wg     *sync.WaitGroup
}

func New(cfg *config.Config) MonitorHub {
	ctx, cancel := context.WithCancel(context.Background())
	return &monitorHub{
		ctx:    ctx,
		cancel: cancel,
		cfg:    cfg,
		wg:     new(sync.WaitGroup),
	}
}

func (mh *monitorHub) Log(critLevel int, message string) {

}

func (mh *monitorHub) RunMonitoring() {
	defer mh.cancel()
	baseMonitors := []*config.BaseFields{
		&mh.cfg.SSHMonitor.BaseFields,
		&mh.cfg.WebBruteMonitor.BaseFields,
		&mh.cfg.WebReconMonitor.BaseFields,
		&mh.cfg.DatabaseMonitor.BaseFields,
	}
	for _, mon := range baseMonitors {
		mh.wg.Go(func() {
			mh.RunBaseMonitor(mon)
		})
	}
	mh.wg.Go(func() {
		mh.RunResourceMonitor(&mh.cfg.ResourceMonitor)
	})
	mh.wg.Wait()
}

func (mh *monitorHub) RunBaseMonitor(bm *config.BaseFields) error {
	outputChan := make(chan string, 1000)
	switch bm.Engine {
	case "docker":
		connectToDocker(mh.ctx, bm.UnitName, outputChan)
	case "journal":
		connectToJournal(mh.ctx, bm.UnitName, outputChan)
	case "syslog":
		connectToSyslog(mh.ctx, bm.LogPath, outputChan)
	default:
		return ErrEngineNotFound
	}
	return nil
}

func (mh *monitorHub) RunResourceMonitor(rm *config.ResourceMonitorConfig) error {
	return nil
}
