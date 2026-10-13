package banpool

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func NewBanPoolForTest(repository Repository, firewall Firewall) BanPool {
	return &banPool{repository: repository, firewall: firewall}
}

func NewRepositoryForTest(db DB) Repository {
	return &repository{db: db}
}

func WaitUnbanForTest(bp BanPool, ctx context.Context, ban *Ban) {
	bp.(*banPool).waitUnban(ctx, ban)
}

func SetUnbanRetryIntervalForTest(interval time.Duration) func() {
	original := unbanRetryInterval
	unbanRetryInterval = interval
	return func() { unbanRetryInterval = original }
}

func MaxUnbanRetriesForTest() int {
	return maxUnbanRetries
}

func stubRunCommand(t *testing.T, fn func(name string, args ...string) ([]byte, error)) {
	t.Helper()
	original := runCommand
	runCommand = fn
	t.Cleanup(func() { runCommand = original })
}

func hasArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func TestFirewallRejectsInvalidIP(t *testing.T) {
	stubRunCommand(t, func(string, ...string) ([]byte, error) {
		t.Fatal("runCommand must not be called for an invalid ip")
		return nil, nil
	})

	fw, _ := NewFirewall("iptables")
	if err := fw.Ban("not-an-ip"); !errors.Is(err, ErrInvalidIP) {
		t.Errorf("Ban() error = %v, want ErrInvalidIP", err)
	}
	if err := fw.Unban("999.999.999.999"); !errors.Is(err, ErrInvalidIP) {
		t.Errorf("Unban() error = %v, want ErrInvalidIP", err)
	}
}

func TestFirewallRejectsReservedIPv4Addresses(t *testing.T) {
	stubRunCommand(t, func(string, ...string) ([]byte, error) {
		t.Fatal("runCommand must not be called for a reserved IPv4 address")
		return nil, nil
	})
	fw, _ := NewFirewall("iptables")
	for _, ip := range []string{"192.0.2.0", "192.0.2.255"} {
		if err := fw.Ban(ip); !errors.Is(err, ErrReservedIPv4Address) {
			t.Errorf("Ban(%q) error = %v, want ErrReservedIPv4Address", ip, err)
		}
	}
}

func TestFirewallBan(t *testing.T) {
	var calls [][]string
	stubRunCommand(t, func(name string, args ...string) ([]byte, error) {
		calls = append(calls, args)
		if hasArg(args, "--check") {
			return nil, errors.New("no rule")
		}
		return nil, nil
	})
	fw, _ := NewFirewall("iptables")
	if err := fw.Ban("10.0.0.1"); err != nil {
		t.Fatalf("Ban() error: %v", err)
	}
	if len(calls) != 2 || !hasArg(calls[1], "--insert") {
		t.Fatalf("Ban() calls = %v, want --check then --insert", calls)
	}
}

func TestFirewallBanUsesConfiguredIPTablesChain(t *testing.T) {
	var calls [][]string
	stubRunCommand(t, func(name string, args ...string) ([]byte, error) {
		calls = append(calls, args)
		if hasArg(args, "--check") {
			return nil, errors.New("no rule")
		}
		return nil, nil
	})

	fw, _ := NewFirewall("iptables", []string{"DOCKER-USER"})
	if err := fw.Ban("10.0.0.1"); err != nil {
		t.Fatalf("Ban() error: %v", err)
	}
	for _, call := range calls {
		if hasArg(call, "DOCKER-USER") {
			return
		}
	}
	t.Fatalf("iptables calls = %v, want DOCKER-USER", calls)
}

func TestFirewallBanSucceedsWhenOneConfiguredChainFails(t *testing.T) {
	stubRunCommand(t, func(name string, args ...string) ([]byte, error) {
		if hasArg(args, "--check") {
			return nil, errors.New("no rule")
		}
		if hasArg(args, "DOCKER-USER") {
			return []byte("missing chain"), errors.New("exit 1")
		}
		return nil, nil
	})

	fw, _ := NewFirewall("iptables", []string{"INPUT", "DOCKER-USER"})
	if err := fw.Ban("10.0.0.1"); err != nil {
		t.Fatalf("Ban() error = %v, want success when INPUT was updated", err)
	}
}

func TestFirewallUnbanAttemptsEveryConfiguredChain(t *testing.T) {
	var dockerDelete bool
	stubRunCommand(t, func(name string, args ...string) ([]byte, error) {
		if hasArg(args, "--check") {
			return nil, nil
		}
		if hasArg(args, "--delete") && hasArg(args, "DOCKER-USER") {
			dockerDelete = true
			return nil, nil
		}
		if hasArg(args, "--delete") {
			return []byte("failed"), errors.New("exit 1")
		}
		return nil, nil
	})

	fw, _ := NewFirewall("iptables", []string{"INPUT", "DOCKER-USER"})
	if err := fw.Unban("10.0.0.1"); !errors.Is(err, ErrCantUnbanIP) {
		t.Fatalf("Unban() error = %v, want ErrCantUnbanIP", err)
	}
	if !dockerDelete {
		t.Fatal("Unban() did not try DOCKER-USER after INPUT failed")
	}
}

func TestNewFirewallCreatesNftablesForwardChainBeforeDocker(t *testing.T) {
	var addChain []string
	stubRunCommand(t, func(name string, args ...string) ([]byte, error) {
		if hasArg(args, "list") {
			return nil, errors.New("missing")
		}
		if hasArg(args, "chain") {
			addChain = args
		}
		return nil, nil
	})

	if _, err := NewFirewall("nftables", []string{nftablesForwardBanChain}); err != nil {
		t.Fatalf("NewFirewall() error: %v", err)
	}
	if !hasArg(addChain, "{ type filter hook forward priority filter - 1; policy accept; }") {
		t.Fatalf("nft add-chain arguments = %v, want forward chain before Docker", addChain)
	}
}

func TestFirewallBanAlreadyPresent(t *testing.T) {
	calls := 0
	stubRunCommand(t, func(string, ...string) ([]byte, error) {
		calls++
		return nil, nil
	})
	fw, _ := NewFirewall("iptables")
	if err := fw.Ban("10.0.0.1"); err != nil {
		t.Fatalf("Ban() error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("Ban() made %d calls, want only the --check probe", calls)
	}
}

func TestFirewallBanInsertFails(t *testing.T) {
	stubRunCommand(t, func(name string, args ...string) ([]byte, error) {
		if hasArg(args, "--check") {
			return nil, errors.New("no rule")
		}
		return []byte("err"), errors.New("exit 1")
	})
	fw, _ := NewFirewall("iptables")
	if err := fw.Ban("10.0.0.1"); !errors.Is(err, ErrCantBanIP) {
		t.Fatalf("Ban() error = %v, want ErrCantBanIP", err)
	}
}

func TestFirewallUnban(t *testing.T) {
	var calls [][]string
	stubRunCommand(t, func(name string, args ...string) ([]byte, error) {
		calls = append(calls, args)
		return nil, nil
	})
	fw, _ := NewFirewall("iptables")
	if err := fw.Unban("10.0.0.1"); err != nil {
		t.Fatalf("Unban() error: %v", err)
	}
	if len(calls) != 2 || !hasArg(calls[1], "--delete") {
		t.Fatalf("Unban() calls = %v, want --check then --delete", calls)
	}
}

func TestFirewallUnbanAbsent(t *testing.T) {
	stubRunCommand(t, func(string, ...string) ([]byte, error) {
		return nil, errors.New("no rule")
	})
	fw, _ := NewFirewall("iptables")
	if err := fw.Unban("10.0.0.1"); err != nil {
		t.Fatalf("Unban() error: %v", err)
	}
}

func TestFirewallUnbanDeleteFails(t *testing.T) {
	stubRunCommand(t, func(name string, args ...string) ([]byte, error) {
		if hasArg(args, "--check") {
			return nil, nil
		}
		return []byte("err"), errors.New("exit 1")
	})
	fw, _ := NewFirewall("iptables")

	if err := fw.Unban("10.0.0.1"); !errors.Is(err, ErrCantUnbanIP) {
		t.Fatalf("Unban() error = %v, want ErrCantUnbanIP", err)
	}
}

func TestNewRepositoryMkdirFails(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(filepath.Join(blocker, "blocked.db")); !errors.Is(err, ErrCantCreateDatabaseDir) {
		t.Fatalf("error = %v, want ErrCantCreateDatabaseDir", err)
	}
}

func TestNewRepositoryOpenFails(t *testing.T) {
	original := openDB
	openDB = func(string) (*sql.DB, error) { return nil, errors.New("boom") }
	t.Cleanup(func() { openDB = original })

	if _, err := NewRepository(filepath.Join(t.TempDir(), "blocked.db")); !errors.Is(err, ErrCantOpenDatabase) {
		t.Fatalf("error = %v, want ErrCantOpenDatabase", err)
	}
}

func TestNewRepositoryCreateTableFails(t *testing.T) {
	if _, err := NewRepository(t.TempDir()); !errors.Is(err, ErrCantCreateTable) {
		t.Fatalf("error = %v, want ErrCantCreateTable", err)
	}
}
