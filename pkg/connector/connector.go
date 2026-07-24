package connector

import (
	"context"
	"open-defender/pkg/config"
	"open-defender/pkg/protocol"
)

type Connector interface {
	Run()
	connect()
}

type connector struct {
	cfg        config.ExporterConfig
	ctx        context.Context
	cancel     context.CancelFunc
	sendChanel chan<- protocol.Envelope
}

func New(cfg config.ExporterConfig, ctx context.Context, cancel context.CancelFunc, sendChanel chan<- protocol.Envelope) Connector {
	return &connector{
		cfg:        cfg,
		ctx:        ctx,
		cancel:     cancel,
		sendChanel: sendChanel,
	}
}

func (c *connector) Run() {
	for {
		select {
		case <-c.ctx.Done():
			break
		default:
		}

	}
}

func (c *connector) connect() {

}
