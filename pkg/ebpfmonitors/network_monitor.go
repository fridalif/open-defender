package ebpfmonitors

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"open-defender/pkg/banpool"
	"open-defender/pkg/config"
	"open-defender/pkg/ebpfmonitors/gobpfs"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package=gobpfs -output-dir=gobpfs NetworkMonitor bpf/network_monitor.bpf.c -- -Ibpf -O2 -Wall -g

type NetworkEvent struct {
	SrcIP    uint32
	DestPort uint16
}

type networkMonitor struct {
	ctx         context.Context
	cancel      context.CancelFunc
	cfg         config.EbpfNetworkAntireconConfig
	bp          banpool.BanPool
	logFunction func(message string, afterAction func())
}

type NetworkMonitor interface {
	Run()
}

func NewNetworkMonitor(ctx context.Context, cancel context.CancelFunc, cfg config.EbpfNetworkAntireconConfig, bp banpool.BanPool, logFunction func(message string, afterAction func())) NetworkMonitor {
	return &networkMonitor{
		ctx:         ctx,
		cancel:      cancel,
		cfg:         cfg,
		bp:          bp,
		logFunction: logFunction,
	}
}

type portSet map[uint16]struct{}

func (nm *networkMonitor) Run() {
	if nm.cfg.Mode == "disabled" {
		return
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Println("ebpfmonitors.Run() -> ", err)
	}

	objs := gobpfs.NetworkMonitorObjects{}
	if err := gobpfs.LoadNetworkMonitorObjects(&objs, nil); err != nil {
		log.Println("ebpfmonitors.Run() -> ", err)
		return
	}
	defer objs.Close()

	tp, err := link.Tracepoint("tcp", "tcp_send_reset", objs.TpTcpSendReset, nil)
	if err != nil {
		log.Println("ebpfmonitors.Run() -> ", err)
		return
	}
	defer tp.Close()

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Println("ebpfmonitors.Run() -> ", err)
		return
	}
	defer reader.Close()

	go func() {
		<-nm.ctx.Done()
		reader.Close()
	}()

	whitelist := portsToSet(nm.cfg.WhitelistPorts)
	blacklist := portsToSet(nm.cfg.BlacklistPorts)

	ipPortsMap := sync.Map{}
	go nm.clearMap(nm.cfg.WindowSeconds, &ipPortsMap)

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Println("ebpfmonitors.Run() -> ", err)
			continue
		}

		event, ok := parseEvent(record.RawSample)
		if !ok {
			continue
		}
		ip := ipString(event.SrcIP)

		if _, banned := whitelist[event.DestPort]; banned {
			continue
		}

		if _, listed := blacklist[event.DestPort]; listed {
			nm.report(ip, fmt.Sprintf("network_antirecon -> ip %s hit blacklisted port %d", ip, event.DestPort))
			continue
		}

		raw, _ := ipPortsMap.LoadOrStore(ip, portSet{})
		ports, ok := raw.(portSet)
		if !ok {
			continue
		}
		ports[event.DestPort] = struct{}{}

		if nm.cfg.PortsCount > 0 && uint64(len(ports)) >= nm.cfg.PortsCount {
			nm.report(ip, fmt.Sprintf("network_antirecon -> ip %s scanned %d ports in %ds window", ip, len(ports), nm.cfg.WindowSeconds))
			ipPortsMap.Delete(ip)
		}
	}
}

func (nm *networkMonitor) report(ip string, message string) {
	afterAction := func() {}
	if nm.cfg.Mode == "blocker" {
		afterAction = func() {
			if err := nm.bp.BanIP(nm.ctx, ip, nm.cfg.BanSeconds); err != nil {
				log.Println(err.Error())
			}
		}
	}
	nm.logFunction(message, afterAction)
}

func (nm *networkMonitor) clearMap(seconds uint64, clearingMap *sync.Map) {
	for {
		select {
		case <-nm.ctx.Done():
			return
		default:
			time.Sleep(time.Duration(seconds) * time.Second)
			clearingMap.Clear()
		}
	}
}

func portsToSet(ports []uint64) map[uint16]struct{} {
	set := make(map[uint16]struct{}, len(ports))
	for _, port := range ports {
		set[uint16(port)] = struct{}{}
	}
	return set
}

func parseEvent(sample []byte) (NetworkEvent, bool) {
	if len(sample) < 6 {
		return NetworkEvent{}, false
	}
	return NetworkEvent{
		SrcIP:    binary.BigEndian.Uint32(sample[0:4]),
		DestPort: binary.BigEndian.Uint16(sample[4:6]),
	}, true
}

func ipString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}
