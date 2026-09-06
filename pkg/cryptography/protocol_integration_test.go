//go:build integration

package cryptography_test

import (
	"encoding/json"
	"testing"

	"open-defender/pkg/cryptography"
	"open-defender/pkg/protocol"
)

// TestEncryptedProtocolEnvelopeIntegration verifies the wire-format path used
// between the agent and dashboard without relying on an external service.
func TestEncryptedProtocolEnvelopeIntegration(t *testing.T) {
	privateKey, publicKey, err := cryptography.GenerateKeys(2048)
	if err != nil {
		t.Fatal(err)
	}

	want, err := protocol.NewEnvelope(
		protocol.ServiceAlert,
		protocol.OpRaised,
		"configuration-id",
		"user-id",
		7,
		protocol.AlertPayload{Events: []protocol.AlertEvent{{
			Source:   protocol.SourceNetworkAntirecon,
			Severity: protocol.SeverityAlert,
			IP:       "198.51.100.4",
			Message:  "port scan detected",
		}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := cryptography.EncryptMessage(publicKey, raw)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := cryptography.DecryptMessage(privateKey, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	var got protocol.Envelope
	if err := json.Unmarshal(decrypted, &got); err != nil {
		t.Fatal(err)
	}
	var payload protocol.AlertPayload
	if err := got.DecodePayload(&payload); err != nil {
		t.Fatal(err)
	}
	if got.TaskID != want.TaskID || len(payload.Events) != 1 || payload.Events[0].IP != "198.51.100.4" {
		t.Fatalf("decoded envelope = %#v, payload = %#v", got, payload)
	}
}
