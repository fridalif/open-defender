//go:build integration

package banpool

import (
	"os"
	"os/exec"
	"testing"
)

const testDocumentationIP = "203.0.113.7"

func TestFirewallIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("not root, skipping iptables integration test")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables not installed, skipping integration test")
	}

	ruleExists := func() bool {
		return exec.Command("iptables", "--check", "INPUT", "--source", testDocumentationIP, "--jump", "DROP").Run() == nil
	}

	// make sure we start clean and always leave clean
	cleanup := func() {
		for ruleExists() {
			exec.Command("iptables", "--delete", "INPUT", "--source", testDocumentationIP, "--jump", "DROP").Run()
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	fw := NewFirewall()

	if err := fw.Ban(testDocumentationIP); err != nil {
		t.Fatalf("Ban() error: %v", err)
	}
	if !ruleExists() {
		t.Fatal("Ban() did not insert an iptables DROP rule")
	}

	// banning again must be idempotent
	if err := fw.Ban(testDocumentationIP); err != nil {
		t.Fatalf("second Ban() error: %v", err)
	}

	if err := fw.Unban(testDocumentationIP); err != nil {
		t.Fatalf("Unban() error: %v", err)
	}
	if ruleExists() {
		t.Fatal("Unban() did not remove the iptables DROP rule")
	}

	// unbanning an absent rule must be a no-op
	if err := fw.Unban(testDocumentationIP); err != nil {
		t.Fatalf("second Unban() error: %v", err)
	}
}
