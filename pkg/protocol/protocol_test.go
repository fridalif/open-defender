package protocol

import (
	"encoding/json"
	"testing"
)

func TestEnvelopePayloadRoundTrip(t *testing.T) {
	want := AlertPayload{Events: []AlertEvent{{Source: SourceSSHMonitor, Message: "failed login"}}}
	envelope, err := NewEnvelope(ServiceAlert, OpRaised, "config", "user", 42, want)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Version != Version || envelope.TaskID != 42 {
		t.Fatalf("envelope = %#v", envelope)
	}

	var got AlertPayload
	if err := envelope.DecodePayload(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Events) != 1 || got.Events[0].Message != want.Events[0].Message {
		t.Errorf("decoded payload = %#v", got)
	}
}

func TestPayloadSpecialCasesAndErrors(t *testing.T) {
	for _, payload := range []any{nil, json.RawMessage(nil)} {
		raw, err := MarshalPayload(payload)
		if err != nil || string(raw) != "{}" {
			t.Fatalf("MarshalPayload(%#v) = %q, %v", payload, raw, err)
		}
	}

	raw := json.RawMessage(`{"raw":true}`)
	got, err := MarshalPayload(raw)
	if err != nil || string(got) != string(raw) {
		t.Fatalf("raw payload = %q, %v", got, err)
	}

	if _, err := MarshalPayload(make(chan int)); err == nil {
		t.Fatal("MarshalPayload() accepted an unsupported value")
	}
	if err := (&Envelope{}).DecodePayload(&struct{}{}); err == nil {
		t.Fatal("DecodePayload() accepted an empty payload")
	}
	if err := (&Envelope{Payload: json.RawMessage("{")}).DecodePayload(&struct{}{}); err == nil {
		t.Fatal("DecodePayload() accepted malformed JSON")
	}
}
