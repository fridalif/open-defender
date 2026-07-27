package monitor

//go:generate mockgen -source=monitor.go -destination=mocks/monitor_mock.go -package=mocks

import (
	"context"
	"fmt"
	"log"
	"open-defender/pkg/banpool"
	"open-defender/pkg/config"
	"open-defender/pkg/connector"
	"open-defender/pkg/ebpfmonitors"
	"open-defender/pkg/protocol"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

var (
	netIOCounters  = net.IOCountersWithContext
	diskIOCounters = disk.IOCountersWithContext
	cpuPercent     = cpu.PercentWithContext
	memVirtual     = mem.VirtualMemoryWithContext
)

var ipPattern = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}`)

type MonitorHub interface {
	RunMonitoring()
	RunBaseMonitor(name string, bm *config.BaseFields) error
	RunResourceMonitor(rm *config.ResourceMonitorConfig) error
	RunNetworkMonitor(nc *config.EbpfNetworkAntireconConfig) error
}

type monitorHub struct {
	cfg        *config.Config
	configPath string
	ctx        context.Context
	cancel     context.CancelFunc
	wg         *sync.WaitGroup
	bp         banpool.BanPool
	exportChan chan protocol.Envelope
	restart    chan struct{}
}

func New(cfg *config.Config, bp banpool.BanPool, configPath string) MonitorHub {
	ctx, cancel := context.WithCancel(context.Background())
	return &monitorHub{
		ctx:        ctx,
		cancel:     cancel,
		cfg:        cfg,
		configPath: configPath,
		wg:         new(sync.WaitGroup),
		bp:         bp,
		exportChan: make(chan protocol.Envelope, exportQueueSize),
		restart:    make(chan struct{}, 1),
	}
}

func (mh *monitorHub) RunMonitoring() {
	for {
		mh.runCycle()

		select {
		case <-mh.restart:
			log.Println("configuration changed, restarting monitors")
			if err := mh.cfg.LoadConfigReadOnly(mh.configPath); err != nil {
				log.Println(err.Error())
				return
			}
			mh.ctx, mh.cancel = context.WithCancel(context.Background())
			mh.wg = new(sync.WaitGroup)
		default:
			return
		}
	}
}

func (mh *monitorHub) runCycle() {
	defer mh.cancel()

	if err := mh.bp.RestoreBans(mh.ctx); err != nil {
		log.Println(err.Error())
	}

	baseMonitors := []struct {
		name string
		bm   *config.BaseFields
	}{
		{protocol.SourceSSHMonitor, &mh.cfg.SSHMonitor.BaseFields},
		{protocol.SourceWebBruteMonitor, &mh.cfg.WebBruteMonitor.BaseFields},
		{protocol.SourceWebReconMonitor, &mh.cfg.WebReconMonitor.BaseFields},
		{protocol.SourceDatabaseMonitor, &mh.cfg.DatabaseMonitor.BaseFields},
	}

	for _, mon := range baseMonitors {
		mh.wg.Go(func() {
			if err := mh.RunBaseMonitor(mon.name, mon.bm); err != nil {
				log.Println(err.Error())
			}
		})
	}
	mh.wg.Go(func() {
		if err := mh.RunResourceMonitor(&mh.cfg.ResourceMonitor); err != nil {
			log.Println(err.Error())
		}
	})
	mh.wg.Go(func() {
		if err := mh.RunNetworkMonitor(&mh.cfg.EbpfMonitors.NetworkAntirecon); err != nil {
			log.Println(err.Error())
		}
	})
	if mh.cfg.Exporter.Enabled && mh.exportChan != nil {
		exporter := connector.New(mh.cfg, mh.configPath, mh.ctx, mh.cancel, mh.exportChan, mh.restart)
		mh.wg.Go(exporter.Run)
	}
	mh.wg.Wait()
}

func (mh *monitorHub) export(event protocol.AlertEvent) {
	if mh.exportChan == nil || !mh.cfg.Exporter.Enabled {
		return
	}
	if event.HappenedAt.IsZero() {
		event.HappenedAt = time.Now().UTC()
	}
	envelope, err := protocol.NewEnvelope(
		protocol.ServiceAlert,
		protocol.OpRaised,
		mh.cfg.Exporter.ConfigID,
		mh.cfg.Exporter.UserID,
		0,
		protocol.AlertPayload{Events: []protocol.AlertEvent{event}},
	)
	if err != nil {
		log.Println(err.Error())
		return
	}
	select {
	case mh.exportChan <- *envelope:
	default:
		log.Println("export queue is full, dropping event")
	}
}

func (mh *monitorHub) withBanEvent(ip string, mode string, afterAction func()) func() {
	return func() {
		afterAction()
		if mode != modeBlocker || ip == "" {
			return
		}
		mh.export(protocol.AlertEvent{
			Source:  protocol.SourceIPBan,
			IP:      ip,
			Message: fmt.Sprintf("ip_ban -> %s is banned", ip),
		})
	}
}

func (mh *monitorHub) getIp(re *regexp.Regexp, message string) (string, bool) {
	matches := re.FindStringSubmatch(message)
	if len(matches) == 0 {
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

var goRun = func(f func()) { go f() }

func (mh *monitorHub) alert(critLevel int, event protocol.AlertEvent, afterAction func()) {
	log.Printf("<%d>%s\n", critLevel, event.Message)
	mh.export(event)
	goRun(afterAction)
}

func (mh *monitorHub) RunNetworkMonitor(nc *config.EbpfNetworkAntireconConfig) error {
	nm := ebpfmonitors.NewNetworkMonitor(mh.ctx, mh.cancel, *nc, mh.bp, func(message string, afterAction func()) {
		ip := ipPattern.FindString(message)
		event := protocol.AlertEvent{
			Source:  protocol.SourceNetworkAntirecon,
			IP:      ip,
			Message: message,
		}
		mh.alert(journalInfo, event, mh.withBanEvent(ip, nc.Mode, afterAction))
	})
	return nm.Run()
}

func (mh *monitorHub) RunBaseMonitor(name string, bm *config.BaseFields) error {
	if bm.Mode == modeDisabled {
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
	if err := startSource(mh.ctx, bm, outputChan); err != nil {
		return err
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
			if bm.Mode == modeBlocker {
				action = func() {
					err := mh.bp.BanIP(mh.ctx, ip, bm.BanSeconds)
					if err != nil {
						log.Println(err.Error())
						return
					}
					mh.export(protocol.AlertEvent{
						Source:  protocol.SourceIPBan,
						IP:      ip,
						Message: fmt.Sprintf("ip_ban -> %s is banned", ip),
					})
				}
			}
			event := protocol.AlertEvent{
				Source:  name,
				IP:      ip,
				Message: fmt.Sprintf("%s -> found offenders ip %s while scanning %s: %s-%s", name, ip, bm.Engine, bm.LogPath, bm.UnitName),
				Details: map[string]any{"engine": bm.Engine, "source": bm.Source()},
			}
			mh.alert(journalInfo, event, action)
			counter = 0
		}
		ipAttemptsMap.Store(ip, counter)
	}
	return nil
}

func (mh *monitorHub) checkResourceMetrics(rm *config.ResourceMonitorConfig) error {
	netBefore, err := netIOCounters(mh.ctx, false)
	if err != nil {
		return fmt.Errorf("monitor.checkResourceMetrics() -> %w: %v", ErrCantGetTrafficUsage, err)
	}
	diskBefore, err := diskIOCounters(mh.ctx)
	if err != nil {
		return fmt.Errorf("monitor.checkResourceMetrics() -> %w: %v", ErrCantGetDiskUsage, err)
	}

	cpuPercents, err := cpuPercent(mh.ctx, windowPollInterval, false)
	if err != nil {
		return fmt.Errorf("monitor.checkResourceMetrics() -> %w: %v", ErrCantGetCPUUsage, err)
	}

	netAfter, err := netIOCounters(mh.ctx, false)
	if err != nil {
		return fmt.Errorf("monitor.checkResourceMetrics() -> %w: %v", ErrCantGetTrafficUsage, err)
	}
	diskAfter, err := diskIOCounters(mh.ctx)
	if err != nil {
		return fmt.Errorf("monitor.checkResourceMetrics() -> %w: %v", ErrCantGetDiskUsage, err)
	}

	v, err := memVirtual(mh.ctx)
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
		message := fmt.Sprintf("resource_monitor -> %s is %.2f%s, alert limit is %d%s", name, value, unit, limits.Alert, unit)
		event := protocol.AlertEvent{
			Source:   protocol.SourceResourceMonitor,
			Severity: protocol.SeverityAlert,
			Message:  message,
			Details:  map[string]any{"metric": name, "value": value, "unit": unit, "limit": limits.Alert},
		}

		mh.alert(journalAlert, event, func() {
			if err := mh.saveSnapshot(snapshotDir); err != nil {
				log.Println(err.Error())
			}
		})

		return
	}

	if limits.Warning != 0 && value >= float64(limits.Warning) {
		message := fmt.Sprintf("resource_monitor -> %s is %.2f%s, warning limit is %d%s", name, value, unit, limits.Warning, unit)
		event := protocol.AlertEvent{
			Source:   protocol.SourceResourceMonitor,
			Severity: protocol.SeverityWarning,
			Message:  message,
			Details:  map[string]any{"metric": name, "value": value, "unit": unit, "limit": limits.Warning},
		}

		mh.alert(journalWarning, event, func() {})
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
