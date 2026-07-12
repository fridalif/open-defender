package monitor

import (
	"context"
	"fmt"
	"log"
	"open-defender/pkg/banpool"
	"open-defender/pkg/config"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
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

	if err := mh.bp.RestoreBans(mh.ctx); err != nil {
		log.Println(err.Error())
	}

	baseMonitors := []*config.BaseFields{
		&mh.cfg.SSHMonitor.BaseFields,
		&mh.cfg.WebBruteMonitor.BaseFields,
		&mh.cfg.WebReconMonitor.BaseFields,
		&mh.cfg.DatabaseMonitor.BaseFields,
	}
	for _, mon := range baseMonitors {
		mh.wg.Go(func() {
			if err := mh.RunBaseMonitor(mon); err != nil {
				log.Println(err.Error())
			}
		})
	}
	mh.wg.Go(func() {
		if err := mh.RunResourceMonitor(&mh.cfg.ResourceMonitor); err != nil {
			log.Println(err.Error())
		}
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
			time.Sleep(time.Duration(seconds) * time.Second)
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
	re, err := regexp.Compile(bm.Pattern)
	go mh.clearMaps(mh.ctx, bm.WindowSeconds, &ipAttemptsMap)
	if err != nil {
		mh.cancel()
		return fmt.Errorf("monitor.RunBaseMonitor() -> %w: %v", ErrCompileRegexp, err)
	}
	switch bm.Engine {
	case "docker":
		go connectToDocker(mh.ctx, mh.cancel, bm.UnitName, outputChan)
	case "journal":
		go connectToJournal(mh.ctx, mh.cancel, bm.UnitName, outputChan)
	case "syslog":
		go connectToSyslog(mh.ctx, mh.cancel, bm.LogPath, outputChan)
	default:
		return fmt.Errorf("monitor.RunBaseMonitor(engine: %s) -> %w", bm.Engine, ErrEngineNotFound)
	}
	for message := range outputChan {
		ip, found := mh.getIp(re, message)
		if !found || slices.Contains(mh.cfg.IPWhiteList, ip) {
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
			mh.alert(journalInfo, fmt.Sprintf("found offenders ip %s while scanning %s: %s-%s", ip, bm.Engine, bm.LogPath, bm.UnitName), action)
			counter = 0
		}
		ipAttemptsMap.Store(ip, counter)
	}
	return nil
}

func (mh *monitorHub) checkResourceMetrics(rm *config.ResourceMonitorConfig) error {
	netBefore, err := net.IOCountersWithContext(mh.ctx, false)
	if err != nil {
		return fmt.Errorf("monitor.checkResourceMetrics() -> %w: %v", ErrCantGetTrafficUsage, err)
	}
	diskBefore, err := disk.IOCountersWithContext(mh.ctx)
	if err != nil {
		return fmt.Errorf("monitor.checkResourceMetrics() -> %w: %v", ErrCantGetDiskUsage, err)
	}

	cpuPercents, err := cpu.PercentWithContext(mh.ctx, windowPollInterval, false)
	if err != nil {
		return fmt.Errorf("monitor.checkResourceMetrics() -> %w: %v", ErrCantGetCPUUsage, err)
	}

	netAfter, err := net.IOCountersWithContext(mh.ctx, false)
	if err != nil {
		return fmt.Errorf("monitor.checkResourceMetrics() -> %w: %v", ErrCantGetTrafficUsage, err)
	}
	diskAfter, err := disk.IOCountersWithContext(mh.ctx)
	if err != nil {
		return fmt.Errorf("monitor.checkResourceMetrics() -> %w: %v", ErrCantGetDiskUsage, err)
	}

	v, err := mem.VirtualMemoryWithContext(mh.ctx)
	if err != nil {
		return fmt.Errorf("monitor.checkResourceMetrics() -> %w: %v", ErrCantGetRAMUsage, err)
	}

	if len(cpuPercents) == 0 {
		return fmt.Errorf("monitor.checkResourceMetrics() -> %w: no measurements", ErrCantGetCPUUsage)
	}

	seconds := windowPollInterval.Seconds()

	cpuPercent := cpuPercents[0]
	ramPercent := v.UsedPercent

	var trafficMBs float64
	if len(netBefore) > 0 && len(netAfter) > 0 {
		rxBytes := netAfter[0].BytesRecv - netBefore[0].BytesRecv
		txBytes := netAfter[0].BytesSent - netBefore[0].BytesSent
		trafficMBs = float64(rxBytes+txBytes) / seconds / 1024 / 1024
	}

	var totalIOps uint64
	for name, after := range diskAfter {
		before, ok := diskBefore[name]
		if !ok {
			continue
		}
		totalIOps += (after.ReadCount - before.ReadCount) + (after.WriteCount - before.WriteCount)
	}
	diskIOps := float64(totalIOps) / seconds

	mh.checkLimits("cpu usage", cpuPercent, "%", rm.CpuUsagePersentage, rm.OutputTopSnapshotDir)
	mh.checkLimits("ram usage", ramPercent, "%", rm.RamUsagePersentage, rm.OutputTopSnapshotDir)
	mh.checkLimits("traffic usage", trafficMBs, "mb/s", rm.TrafficUsageMBs, rm.OutputTopSnapshotDir)
	mh.checkLimits("disk usage", diskIOps, "iops", rm.DiskUsageIOps, rm.OutputTopSnapshotDir)

	return nil
}

func (mh *monitorHub) checkLimits(name string, value float64, unit string, limits config.ResourceFields, snapshotDir string) {
	if limits.Alert != 0 && value >= float64(limits.Alert) {
		message := fmt.Sprintf("%s is %.2f%s, alert limit is %d%s", name, value, unit, limits.Alert, unit)

		mh.alert(journalAlert, message, func() {
			if err := mh.saveSnapshot(snapshotDir); err != nil {
				log.Println(err.Error())
			}
		})

		return
	}

	if limits.Warning != 0 && value >= float64(limits.Warning) {
		message := fmt.Sprintf("%s is %.2f%s, warning limit is %d%s", name, value, unit, limits.Warning, unit)

		mh.alert(journalWarning, message, func() {})
	}
}

func (mh *monitorHub) RunResourceMonitor(rm *config.ResourceMonitorConfig) error {
	if !rm.Enabled {
		return nil
	}

	ticker := time.NewTicker(resourcePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-mh.ctx.Done():
			return nil

		case <-ticker.C:
			if err := mh.checkResourceMetrics(rm); err != nil {
				log.Println("RunResourceMonitor() -> ", err)
			}
		}
	}
}
