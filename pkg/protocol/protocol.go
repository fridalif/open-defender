package protocol

import (
	"encoding/json"
	"fmt"
	"time"
)

const Version = 2

const (
	ServiceSystem = "system"
	ServiceConfig = "config"
	ServiceAlert  = "alert"
)

const (
	OpHello     = "hello"
	OpAck       = "ack"
	OpSetConfig = "set_config"
	OpGetConfig = "get_config"
	OpConfig    = "config"
	OpRaised    = "raised"
)

const (
	SourceSSHMonitor       = "ssh_monitor"
	SourceWebBruteMonitor  = "web_brute_monitor"
	SourceWebReconMonitor  = "web_recon_monitor"
	SourceDatabaseMonitor  = "database_monitor"
	SourceNetworkAntirecon = "network_antirecon"
	SourceResourceMonitor  = "resource_monitor"
	SourceIPBan            = "ip_ban"
)

const (
	SeverityWarning = "warning"
	SeverityAlert   = "alert"
)

const (
	StatusOK    = "ok"
	StatusError = "error"
)

const (
	DashboardAlert           = "alert"
	DashboardConfigUpdated   = "config_updated"
	DashboardOperationStatus = "operation_status"
)

type Envelope struct {
	Version         int             `json:"version"`
	TaskID          int64           `json:"task_id"`
	Service         string          `json:"service"`
	Operation       string          `json:"operation"`
	ConfigurationID string          `json:"configuration_id"`
	UserID          string          `json:"user_id"`
	Payload         json.RawMessage `json:"payload"`
}

type HelloPayload struct {
	PublicKey    string `json:"public_key"`
	AgentVersion string `json:"agent_version"`
}

type AckPayload struct {
	Status string `json:"status"`
	Error  string `json:"error"`
}

type ConfigPayload struct {
	Config json.RawMessage `json:"config"`
}

type AlertEvent struct {
	Source     string         `json:"source"`
	Severity   string         `json:"severity,omitempty"`
	IP         string         `json:"ip,omitempty"`
	Message    string         `json:"message"`
	HappenedAt time.Time      `json:"happened_at"`
	Details    map[string]any `json:"details,omitempty"`
}

type AlertPayload struct {
	Events []AlertEvent `json:"events"`
}

func NewEnvelope(service, operation, configurationID, userID string, taskID int64, payload any) (*Envelope, error) {
	raw, err := marshalPayload(payload)
	if err != nil {
		return nil, fmt.Errorf("protocol.NewEnvelope: %w", err)
	}
	return &Envelope{
		Version:         Version,
		TaskID:          taskID,
		Service:         service,
		Operation:       operation,
		ConfigurationID: configurationID,
		UserID:          userID,
		Payload:         raw,
	}, nil
}

func (e *Envelope) DecodePayload(target any) error {
	if len(e.Payload) == 0 {
		return fmt.Errorf("protocol.DecodePayload: empty payload")
	}
	if err := json.Unmarshal(e.Payload, target); err != nil {
		return fmt.Errorf("protocol.DecodePayload: %w", err)
	}
	return nil
}

func MarshalPayload(payload any) (json.RawMessage, error) {
	return marshalPayload(payload)
}

func marshalPayload(payload any) (json.RawMessage, error) {
	if payload == nil {
		return json.RawMessage("{}"), nil
	}
	if raw, ok := payload.(json.RawMessage); ok {
		if len(raw) == 0 {
			return json.RawMessage("{}"), nil
		}
		return raw, nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return raw, nil
}
