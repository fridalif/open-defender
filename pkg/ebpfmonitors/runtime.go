package ebpfmonitors

import (
	"context"
	"open-defender/pkg/config"
)

type ebpfMonitorRuntime struct {
	ebpfConfig config.EbpfConfig
	ctx        context.Context
	cancel     context.CancelFunc
}

type EbpfMonitorRuntime interface{}

func New(ctx context.Context, cancel context.CancelFunc, ebpfConfig config.EbpfConfig) EbpfMonitorRuntime {
	return ebpfMonitorRuntime{
		ctx:        ctx,
		cancel:     cancel,
		ebpfConfig: ebpfConfig,
	}
}
