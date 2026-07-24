package connector

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"open-defender/pkg/config"
	"open-defender/pkg/protocol"
	"time"

	"github.com/gorilla/websocket"
)

type Connector interface {
	Run()
	connect() error
	serve() error
	send(message protocol.Envelope) error
}

type connector struct {
	cfg        config.ExporterConfig
	ctx        context.Context
	cancel     context.CancelFunc
	sendChanel <-chan protocol.Envelope
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	ws         *websocket.Conn
}

func New(cfg config.ExporterConfig, ctx context.Context, cancel context.CancelFunc, sendChanel <-chan protocol.Envelope) Connector {
	return &connector{
		cfg:        cfg,
		ctx:        ctx,
		cancel:     cancel,
		sendChanel: sendChanel,
		privateKey: nil,
		publicKey:  nil,
	}
}

func (c *connector) Run() {
	retrySleep := 5
	for {
		select {
		case <-c.ctx.Done():
			break
		default:
		}

		time.Sleep(time.Duration(retrySleep) * time.Second)
		err := c.connect()
		if err != nil {
			log.Println("failed connect to export server: %w", err)
			if retrySleep < 100 {
				retrySleep += 10
			}
			continue
		}
		retrySleep = 5
		err = c.serve()
		if err != nil {
			log.Println(err)
		}
		if errors.Is(err, ErrSomethingWrongInWriteChanel) {
			c.cancel()
			return
		}
	}
}

func (c *connector) connect() error {

}

func (c *connector) serve() error {
	defer func() {
		if c.ws != nil {
			c.ws.Close()
			c.ws = nil
		}
	}()

	for {
		select {
		case <-c.ctx.Done():
			return nil
		case message, ok := <-c.sendChanel:
			if !ok {
				return fmt.Errorf("connector.serve(): %w", ErrSomethingWrongInWriteChanel)
			}
			err := c.send(message)
			if err != nil {
				return err
			}
		}
	}
}

func (c *connector) send(message protocol.Envelope) error {
	if c.ws == nil {
		return fmt.Errorf("connector.serve()->send():%w", ErrWebscoketIsNull)
	}
}
