package connector

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"open-defender/pkg/config"
	"open-defender/pkg/cryptography"
	"open-defender/pkg/protocol"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	agentVersion     = "v1.3.0"
	keyBits          = 2048
	dialTimeout      = 15 * time.Second
	handshakeTimeout = 30 * time.Second
	readWait         = 90 * time.Second
	writeWait        = 15 * time.Second
	maxMessageBytes  = 1 << 20
	minRetrySleep    = 5
	maxRetrySleep    = 100
	retrySleepStep   = 10
)

type Connector interface {
	Run()
	connect() error
	serve() error
	send(message protocol.Envelope) error
}

type connector struct {
	cfg        *config.Config
	configPath string
	ctx        context.Context
	cancel     context.CancelFunc
	sendChanel <-chan protocol.Envelope
	restart    chan<- struct{}
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	serverKey  *rsa.PublicKey
	ws         *websocket.Conn
	wsMutex    *sync.Mutex
	readErrors chan error
	readDone   chan struct{}
}

func New(cfg *config.Config, configPath string, ctx context.Context, cancel context.CancelFunc, sendChanel <-chan protocol.Envelope, restart chan<- struct{}) Connector {
	return &connector{
		cfg:        cfg,
		configPath: configPath,
		ctx:        ctx,
		cancel:     cancel,
		sendChanel: sendChanel,
		restart:    restart,
		privateKey: nil,
		publicKey:  nil,
		wsMutex:    new(sync.Mutex),
	}
}

func (c *connector) Run() {
	retrySleep := minRetrySleep
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		if err := c.sleep(time.Duration(retrySleep) * time.Second); err != nil {
			return
		}

		if err := c.connect(); err != nil {
			log.Printf("connector.Run(): %v", err)
			if retrySleep < maxRetrySleep {
				retrySleep += retrySleepStep
			}
			continue
		}
		retrySleep = minRetrySleep

		err := c.serve()
		if err != nil {
			log.Println(err)
		}
		if errors.Is(err, ErrSomethingWrongInWriteChanel) {
			c.cancel()
			return
		}
	}
}

func (c *connector) sleep(duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-c.ctx.Done():
		return c.ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *connector) connect() error {
	privateKey, publicKey, err := cryptography.GenerateKeys(keyBits)
	if err != nil {
		return fmt.Errorf("connector.connect(): %w", err)
	}
	c.privateKey = privateKey
	c.publicKey = publicKey

	serverKey, err := c.parseServerKey()
	if err != nil {
		return err
	}
	c.serverKey = serverKey

	dialer := &websocket.Dialer{HandshakeTimeout: dialTimeout}
	ws, _, err := dialer.DialContext(c.ctx, c.cfg.Exporter.EndpointAddress, nil)
	if err != nil {
		return fmt.Errorf("connector.connect(): %w: %v", ErrCantDialEndpoint, err)
	}

	c.wsMutex.Lock()
	c.ws = ws
	c.wsMutex.Unlock()

	ws.SetReadLimit(maxMessageBytes)
	ws.SetPingHandler(func(payload string) error {
		if err := ws.SetReadDeadline(time.Now().Add(readWait)); err != nil {
			return err
		}
		c.wsMutex.Lock()
		defer c.wsMutex.Unlock()
		return ws.WriteControl(websocket.PongMessage, []byte(payload), time.Now().Add(writeWait))
	})

	if err := c.handshake(); err != nil {
		c.closeWS()
		return err
	}

	c.readErrors = make(chan error, 1)
	c.readDone = make(chan struct{})
	go c.readLoop(ws, privateKey, c.readErrors, c.readDone)

	return nil
}

func (c *connector) parseServerKey() (*rsa.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(c.cfg.Exporter.EndpointRsaPublicKey)
	if err != nil {
		return nil, fmt.Errorf("connector.parseServerKey(): %w: %v", ErrBadEndpointKey, err)
	}
	key, err := x509.ParsePKCS1PublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("connector.parseServerKey(): %w: %v", ErrBadEndpointKey, err)
	}
	return key, nil
}

func (c *connector) handshake() error {
	hello, err := protocol.NewEnvelope(
		protocol.ServiceSystem,
		protocol.OpHello,
		c.cfg.Exporter.ConfigID,
		c.cfg.Exporter.UserID,
		0,
		protocol.HelloPayload{
			PublicKey:    base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(c.publicKey)),
			AgentVersion: agentVersion,
		},
	)
	if err != nil {
		return fmt.Errorf("connector.handshake(): %w", err)
	}
	if err := c.send(*hello); err != nil {
		return fmt.Errorf("connector.handshake(): %w", err)
	}

	envelope, err := c.read(handshakeTimeout)
	if err != nil {
		return fmt.Errorf("connector.handshake(): %w", err)
	}
	if envelope.Service != protocol.ServiceConfig || envelope.Operation != protocol.OpSetConfig {
		return fmt.Errorf("connector.handshake(): %w: %s/%s", ErrUnexpectedMessage, envelope.Service, envelope.Operation)
	}

	changed, applyErr := c.applyConfig(*envelope)
	if err := c.acknowledge(envelope.TaskID, applyErr); err != nil {
		return fmt.Errorf("connector.handshake(): %w", err)
	}
	if applyErr != nil {
		return fmt.Errorf("connector.handshake(): %w", applyErr)
	}
	if changed {
		c.requestRestart()
	}
	return nil
}

func (c *connector) serve() error {
	defer func() {
		c.closeWS()
		if c.readDone != nil {
			<-c.readDone
		}
	}()

	for {
		select {
		case <-c.ctx.Done():
			return nil
		case err := <-c.readErrors:
			return fmt.Errorf("connector.serve(): %w", err)
		case message, ok := <-c.sendChanel:
			if !ok {
				return fmt.Errorf("connector.serve(): %w", ErrSomethingWrongInWriteChanel)
			}
			err := c.send(message)
			if err != nil {
				return fmt.Errorf("connector.serve(): %w", err)
			}
		}
	}
}

func (c *connector) readLoop(ws *websocket.Conn, privateKey *rsa.PrivateKey, readErrors chan error, done chan struct{}) {
	defer close(done)

	for {
		envelope, err := c.readFrom(ws, privateKey, readWait)
		if err != nil {
			select {
			case readErrors <- err:
			default:
			}
			return
		}
		if err := c.handle(*envelope); err != nil {
			log.Println(err)
		}
	}
}

func (c *connector) handle(envelope protocol.Envelope) error {
	switch {
	case envelope.Service == protocol.ServiceConfig && envelope.Operation == protocol.OpSetConfig:
		changed, applyErr := c.applyConfig(envelope)
		if err := c.acknowledge(envelope.TaskID, applyErr); err != nil {
			return fmt.Errorf("connector.handle(): %w", err)
		}
		if applyErr != nil {
			return fmt.Errorf("connector.handle(): %w", applyErr)
		}
		if changed {
			c.requestRestart()
		}
		return nil

	case envelope.Service == protocol.ServiceConfig && envelope.Operation == protocol.OpGetConfig:
		return c.sendConfig(envelope.TaskID)

	default:
		return fmt.Errorf("connector.handle(): %w: %s/%s", ErrUnexpectedMessage, envelope.Service, envelope.Operation)
	}
}

func (c *connector) applyConfig(envelope protocol.Envelope) (bool, error) {
	var payload protocol.ConfigPayload
	if err := envelope.DecodePayload(&payload); err != nil {
		return false, fmt.Errorf("connector.applyConfig(): %w", err)
	}

	incoming := config.New()
	if err := json.Unmarshal(payload.Config, incoming); err != nil {
		return false, fmt.Errorf("connector.applyConfig(): %w: %v", ErrBadConfigPayload, err)
	}

	incoming.Exporter = c.cfg.Exporter
	incoming.IPWhiteList = c.keepLocalIps(incoming.IPWhiteList)

	if problems := incoming.Validate(); len(problems) != 0 {
		return false, fmt.Errorf("connector.applyConfig(): %w: %v", config.ErrInvalidConfig, problems)
	}

	if reflect.DeepEqual(*incoming, *c.cfg) {
		return false, nil
	}

	if err := incoming.SaveConfig(c.configPath); err != nil {
		return false, fmt.Errorf("connector.applyConfig(): %w", err)
	}
	return true, nil
}

func (c *connector) keepLocalIps(whitelist []string) []string {
	local, err := c.cfg.GetLocalIps()
	if err != nil {
		log.Printf("connector.keepLocalIps(): %v", err)
		return whitelist
	}
	if whitelist == nil {
		whitelist = []string{}
	}
	for _, ip := range local {
		if !slices.Contains(whitelist, ip) {
			whitelist = append(whitelist, ip)
		}
	}
	return whitelist
}

func (c *connector) sendConfig(taskID int64) error {
	raw, err := json.Marshal(c.cfg)
	if err != nil {
		return fmt.Errorf("connector.sendConfig(): %w", err)
	}
	envelope, err := protocol.NewEnvelope(
		protocol.ServiceConfig,
		protocol.OpConfig,
		c.cfg.Exporter.ConfigID,
		c.cfg.Exporter.UserID,
		taskID,
		protocol.ConfigPayload{Config: raw},
	)
	if err != nil {
		return fmt.Errorf("connector.sendConfig(): %w", err)
	}
	return c.send(*envelope)
}

func (c *connector) acknowledge(taskID int64, applyErr error) error {
	payload := protocol.AckPayload{Status: protocol.StatusOK}
	if applyErr != nil {
		payload.Status = protocol.StatusError
		payload.Error = applyErr.Error()
	}
	envelope, err := protocol.NewEnvelope(
		protocol.ServiceSystem,
		protocol.OpAck,
		c.cfg.Exporter.ConfigID,
		c.cfg.Exporter.UserID,
		taskID,
		payload,
	)
	if err != nil {
		return fmt.Errorf("connector.acknowledge(): %w", err)
	}
	return c.send(*envelope)
}

func (c *connector) requestRestart() {
	select {
	case c.restart <- struct{}{}:
	default:
	}
	c.cancel()
}

func (c *connector) read(budget time.Duration) (*protocol.Envelope, error) {
	c.wsMutex.Lock()
	ws := c.ws
	c.wsMutex.Unlock()
	return c.readFrom(ws, c.privateKey, budget)
}

func (c *connector) readFrom(ws *websocket.Conn, privateKey *rsa.PrivateKey, budget time.Duration) (*protocol.Envelope, error) {
	if ws == nil {
		return nil, fmt.Errorf("connector.read(): %w", ErrWebscoketIsNull)
	}
	if err := ws.SetReadDeadline(time.Now().Add(budget)); err != nil {
		return nil, fmt.Errorf("connector.read(): %w", err)
	}
	_, raw, err := ws.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("connector.read(): %w", err)
	}
	decrypted, err := cryptography.DecryptMessage(privateKey, raw)
	if err != nil {
		return nil, fmt.Errorf("connector.read(): %w", err)
	}
	var envelope protocol.Envelope
	if err := json.Unmarshal(decrypted, &envelope); err != nil {
		return nil, fmt.Errorf("connector.read(): %w", err)
	}
	if envelope.Version != protocol.Version {
		return nil, fmt.Errorf("connector.read(): %w: %d", ErrUnsupportedVersion, envelope.Version)
	}
	return &envelope, nil
}

func (c *connector) send(message protocol.Envelope) error {
	c.wsMutex.Lock()
	defer c.wsMutex.Unlock()

	if c.ws == nil {
		return fmt.Errorf("connector.send(): %w", ErrWebscoketIsNull)
	}
	raw, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("connector.send(): %w", err)
	}
	encrypted, err := cryptography.EncryptMessage(c.serverKey, raw)
	if err != nil {
		return fmt.Errorf("connector.send(): %w", err)
	}
	if err := c.ws.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
		return fmt.Errorf("connector.send(): %w", err)
	}
	if err := c.ws.WriteMessage(websocket.TextMessage, encrypted); err != nil {
		return fmt.Errorf("connector.send(): %w", err)
	}
	return nil
}

func (c *connector) closeWS() {
	c.wsMutex.Lock()
	defer c.wsMutex.Unlock()
	if c.ws != nil {
		c.ws.Close()
		c.ws = nil
	}
}
