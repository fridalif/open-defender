package connector

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"open-defender/pkg/config"
	"open-defender/pkg/cryptography"
	"open-defender/pkg/protocol"

	"github.com/gorilla/websocket"
)

func validConfig() *config.Config {
	cfg := config.New()
	cfg.SSHMonitor.Mode = "disabled"
	cfg.WebReconMonitor.Mode = "disabled"
	cfg.WebBruteMonitor.Mode = "disabled"
	cfg.DatabaseMonitor.Mode = "disabled"
	return cfg
}

func TestNewAndCancellationHelpers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	restart := make(chan struct{}, 1)
	c := New(validConfig(), "config.yaml", ctx, cancel, make(chan protocol.Envelope), restart).(*connector)
	if c.wsMutex == nil || c.cfg == nil {
		t.Fatal("New() did not initialise connector state")
	}

	cancel()
	if err := c.sleep(time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("sleep() error = %v, want context.Canceled", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	c.ctx, c.cancel = ctx, cancel
	c.requestRestart()
	select {
	case <-restart:
	case <-time.After(time.Second):
		t.Fatal("requestRestart() did not signal restart")
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("requestRestart() did not cancel context")
	}
}

func TestParseServerKeyAndNilWebsocket(t *testing.T) {
	_, publicKey, err := cryptography.GenerateKeys(2048)
	if err != nil {
		t.Fatal(err)
	}
	c := &connector{cfg: validConfig(), wsMutex: new(sync.Mutex)}
	c.cfg.Exporter.EndpointRsaPublicKey = base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(publicKey))
	parsed, err := c.parseServerKey()
	if err != nil || parsed.N.Cmp(publicKey.N) != 0 {
		t.Fatalf("parseServerKey() = %v, %v", parsed, err)
	}
	c.cfg.Exporter.EndpointRsaPublicKey = "not base64"
	if _, err := c.parseServerKey(); !errors.Is(err, ErrBadEndpointKey) {
		t.Fatalf("error = %v, want ErrBadEndpointKey", err)
	}
	if _, err := c.readFrom(nil, nil, time.Second); !errors.Is(err, ErrWebscoketIsNull) {
		t.Fatalf("readFrom(nil) error = %v", err)
	}
	if err := c.send(protocol.Envelope{}); !errors.Is(err, ErrWebscoketIsNull) {
		t.Fatalf("send() error = %v", err)
	}
}

func TestApplyConfigAndUnexpectedMessage(t *testing.T) {
	cfg := validConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &connector{cfg: cfg, configPath: filepath.Join(t.TempDir(), "nested", "config.yaml"), ctx: ctx, cancel: cancel, wsMutex: new(sync.Mutex)}

	incoming := validConfig()
	incoming.IPWhiteList = []string{"203.0.113.9"}
	raw, err := protocol.MarshalPayload(incoming)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := protocol.NewEnvelope(protocol.ServiceConfig, protocol.OpSetConfig, "", "", 1, protocol.ConfigPayload{Config: raw})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := c.applyConfig(*envelope)
	if err != nil || !changed {
		t.Fatalf("applyConfig() = %v, %v", changed, err)
	}
	if _, err := os.Stat(c.configPath); err != nil {
		t.Fatalf("config was not saved: %v", err)
	}

	bad, err := protocol.NewEnvelope(protocol.ServiceConfig, protocol.OpSetConfig, "", "", 1, protocol.ConfigPayload{Config: json.RawMessage(`"not a config"`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.applyConfig(*bad); !errors.Is(err, ErrBadConfigPayload) {
		t.Fatalf("error = %v, want ErrBadConfigPayload", err)
	}
	if err := c.handle(protocol.Envelope{Service: "unknown", Operation: "nope"}); !errors.Is(err, ErrUnexpectedMessage) {
		t.Fatalf("handle() error = %v, want ErrUnexpectedMessage", err)
	}
}

func TestConnectHandshakeIntegration(t *testing.T) {
	serverPrivate, serverPublic, err := cryptography.GenerateKeys(2048)
	if err != nil {
		t.Fatal(err)
	}
	serverErr := make(chan error, 1)
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			serverErr <- err
			return
		}
		defer ws.Close()
		_, raw, err := ws.ReadMessage()
		if err != nil {
			serverErr <- err
			return
		}
		plain, err := cryptography.DecryptMessage(serverPrivate, raw)
		if err != nil {
			serverErr <- err
			return
		}
		var hello protocol.Envelope
		if err := json.Unmarshal(plain, &hello); err != nil {
			serverErr <- err
			return
		}
		var helloPayload protocol.HelloPayload
		if err := hello.DecodePayload(&helloPayload); err != nil {
			serverErr <- err
			return
		}
		keyBytes, err := base64.StdEncoding.DecodeString(helloPayload.PublicKey)
		if err != nil {
			serverErr <- err
			return
		}
		clientKey, err := x509.ParsePKCS1PublicKey(keyBytes)
		if err != nil {
			serverErr <- err
			return
		}
		incoming := validConfig()
		incoming.IPWhiteList = []string{"203.0.113.8"}
		configRaw, _ := json.Marshal(incoming)
		response, _ := protocol.NewEnvelope(protocol.ServiceConfig, protocol.OpSetConfig, "", "", 123, protocol.ConfigPayload{Config: configRaw})
		responseRaw, _ := json.Marshal(response)
		ciphertext, err := cryptography.EncryptMessage(clientKey, responseRaw)
		if err != nil {
			serverErr <- err
			return
		}
		if err := ws.WriteMessage(websocket.BinaryMessage, ciphertext); err != nil {
			serverErr <- err
			return
		}
		_, raw, err = ws.ReadMessage()
		if err != nil {
			serverErr <- err
			return
		}
		plain, err = cryptography.DecryptMessage(serverPrivate, raw)
		if err != nil {
			serverErr <- err
			return
		}
		var ack protocol.Envelope
		if err := json.Unmarshal(plain, &ack); err != nil {
			serverErr <- err
			return
		}
		var ackPayload protocol.AckPayload
		if err := ack.DecodePayload(&ackPayload); err != nil || ack.TaskID != 123 || ackPayload.Status != protocol.StatusOK {
			serverErr <- fmt.Errorf("invalid acknowledgement: %#v, %v", ack, err)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := validConfig()
	cfg.Exporter.EndpointAddress = "ws" + server.URL[len("http"):]
	cfg.Exporter.EndpointRsaPublicKey = base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(serverPublic))
	c := New(cfg, filepath.Join(t.TempDir(), "config.yaml"), ctx, cancel, make(chan protocol.Envelope), make(chan struct{}, 1)).(*connector)
	if err := c.connect(); err != nil {
		t.Fatalf("connect() error = %v", err)
	}
	c.closeWS()
	select {
	case <-c.readDone:
	case <-time.After(time.Second):
		t.Fatal("read loop did not stop after websocket close")
	}
	select {
	case err := <-serverErr:
		t.Fatal(err)
	default:
	}
}
