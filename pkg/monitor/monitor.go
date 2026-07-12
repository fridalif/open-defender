package monitor

import (
	"context"
	"fmt"
	"log"
	"open-defender/pkg/banpool"
	"open-defender/pkg/config"
	"regexp"
	"sync"
	"time"
)

type MonitorHub interface {
	RunMonitoring()
	RunBaseMonitor(bm *config.BaseFields) error
	RunResourceMonitor(rm *config.ResourceMonitorConfig) error
}

type monitorHub struct {
	cfg    *config.Config
	ctx    context.Context
	cancel context.CancelFunc
	wg     *sync.WaitGroup
	bp     banpool.BanPool
}

func New(cfg *config.Config, bp banpool.BanPool) MonitorHub {
	ctx, cancel := context.WithCancel(context.Background())
	return &monitorHub{
		ctx:    ctx,
		cancel: cancel,
		cfg:    cfg,
		wg:     new(sync.WaitGroup),
		bp:     bp,
	}
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

func (mh *monitorHub) getIp(re *regexp.Regexp, message string) (string, bool) {
	matches := re.FindStringSubmatch(message)
	if matches == nil || len(matches) == 0 {
		return "", false
	}
	for i, name := range re.SubexpNames() {
		if name == "ip" {
			return matches[i], true
		}
	}
	return "", false

}

func (mh *monitorHub) clearMaps(ctx context.Context, seconds uint64, clearingMap *sync.Map) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			time.Sleep(time.Duration(seconds))
			clearingMap.Clear()
		}
	}
}

func (mh *monitorHub) alert(critLevel int, message string, afterAction func()) {
	log.Printf("<%d>%s\n", critLevel, message)
	go afterAction()
}

func (mh *monitorHub) RunBaseMonitor(bm *config.BaseFields) error {
	if bm.Mode == "disabled" {
		return nil
	}
	outputChan := make(chan string, 1000)
	ipAttemptsMap := sync.Map{}
	re := regexp.MustCompile(bm.Pattern)
	switch bm.Engine {
	case "docker":
		go connectToDocker(mh.ctx, mh.cancel, bm.UnitName, outputChan)
	case "journal":
		go connectToJournal(mh.ctx, mh.cancel, bm.UnitName, outputChan)
	case "syslog":
		go connectToSyslog(mh.ctx, mh.cancel, bm.LogPath, outputChan)
	default:
		return ErrEngineNotFound
	}
	for message := range outputChan {
		ip, found := mh.getIp(re, message)
		if !found {
			continue
		}
		raw, _ := ipAttemptsMap.LoadOrStore(ip, uint64(0))
		counter, ok := raw.(uint64)
		if !ok {
			continue
		}
		counter += uint64(1)
		if counter >= bm.Tries {
			action := func() {}
			if bm.Mode == "blocker" {
				action = func() {
					err := mh.bp.BanIP(mh.ctx, ip, bm.BanSeconds)
					if err != nil {
						log.Println(err.Error())
					}
				}
			}
			mh.alert(journalInfo, fmt.Sprintf("banned ip %s while scanning %s: %s-%s", ip, bm.Engine, bm.LogPath, bm.UnitName), action)
		}
	}
	return nil
}

func (mh *monitorHub) RunResourceMonitor(rm *config.ResourceMonitorConfig) error {
	return nil
}
