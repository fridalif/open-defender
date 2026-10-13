package banpool

//go:generate mockgen -source=firewall.go -destination=mocks/firewall_mock.go -package=mocks

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

const (
	nftablesBanChain        = "open_defender"
	nftablesForwardBanChain = "open_defender_forward"
	firewalldDockerPolicy   = "open-defender-dkr"
	dockerUserChain         = "DOCKER-USER"
)

var runCommand = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

type Firewall interface {
	Ban(ip string) error
	Unban(ip string) error
}

type firewall struct {
	fwEngine string
	chains   []string
}

// chains is optional to preserve the default host firewall behaviour for
// callers outside the application configuration.
func NewFirewall(fwEngine string, chains ...[]string) (Firewall, error) {
	firewallChains := []string{"INPUT"}
	if len(chains) != 0 && len(chains[0]) != 0 {
		firewallChains = chains[0]
	}
	if fwEngine == "nftables" && len(chains) == 0 {
		firewallChains = []string{nftablesBanChain}
	}

	fw := &firewall{fwEngine: fwEngine, chains: firewallChains}
	if fwEngine == "nftables" {
		if _, err := runCommand("nft", "list", "table", "inet", "filter"); err != nil {
			if output, addErr := runCommand("nft", "add", "table", "inet", "filter"); addErr != nil {
				return &firewall{}, fmt.Errorf("banpool.firewall.NewFirewall -> %v: %s", addErr, output)
			}
		}

		for _, chain := range firewallChains {
			if err := fw.ensureNftablesChain(chain); err != nil {
				return &firewall{}, err
			}
		}
	}
	if fwEngine == "firewalld" && fw.hasChain(dockerUserChain) {
		if err := fw.ensureFirewalldDockerPolicy(); err != nil {
			return &firewall{}, err
		}
	}
	return fw, nil
}

func (f *firewall) hasChain(want string) bool {
	for _, chain := range f.chains {
		if chain == want {
			return true
		}
	}
	return false
}

func (f *firewall) ensureFirewalldDockerPolicy() error {
	if _, err := runCommand("firewall-cmd", "--info-policy", firewalldDockerPolicy); err == nil {
		return nil
	}

	commands := [][]string{
		{"--new-policy", firewalldDockerPolicy},
		{"--policy", firewalldDockerPolicy, "--add-ingress-zone", "ANY"},
		{"--policy", firewalldDockerPolicy, "--add-egress-zone", "docker"},
		{"--policy", firewalldDockerPolicy, "--set-priority", "-100"},
	}
	for _, args := range commands {
		if output, err := runCommand("firewall-cmd", args...); err != nil {
			return fmt.Errorf("banpool.firewall.NewFirewall -> cannot configure firewalld Docker policy: %v: %s", err, output)
		}
	}
	return nil
}

func (f *firewall) ensureNftablesChain(chain string) error {
	if _, err := runCommand("nft", "list", "chain", "inet", "filter", chain); err == nil {
		return nil
	}

	definition := ""
	switch chain {
	case nftablesBanChain:
		definition = "{ type filter hook input priority filter; policy accept; }"
	case nftablesForwardBanChain:
		definition = "{ type filter hook forward priority filter - 1; policy accept; }"
	default:
		return fmt.Errorf("banpool.firewall.NewFirewall -> unsupported nftables chain: %s", chain)
	}

	if output, err := runCommand("nft", "add", "chain", "inet", "filter", chain, definition); err != nil {
		return fmt.Errorf("banpool.firewall.NewFirewall -> %v: %s", err, output)
	}

	return nil
}

func (f *firewall) Ban(ip string) error {
	if err := validateBanIP(ip); err != nil {
		return fmt.Errorf("banpool.firewall.Ban(ip: %s) -> %w", ip, err)
	}

	if f.hasRule(ip) {
		return nil
	}
	switch f.fwEngine {
	case "iptables":
		for _, chain := range f.chains {
			if output, err := runCommand("iptables", "--insert", chain, "--source", ip, "--jump", "DROP"); err != nil {
				return fmt.Errorf("banpool.firewall.Ban(ip: %s) -> %w: %v: %s", ip, ErrCantBanIP, err, output)
			}
		}
	case "nftables":
		for _, chain := range f.chains {
			if output, err := runCommand("nft", "insert", "rule", "inet", "filter", chain, "ip", "saddr", ip, "drop"); err != nil {
				return fmt.Errorf("banpool.firewall.Ban(ip: %s) -> %w: %v: %s", ip, ErrCantBanIP, err, output)
			}
		}
	case "firewalld":
		for _, chain := range f.chains {
			if err := f.changeFirewalldRule(chain, "--add-rich-rule", ip, ErrCantBanIP); err != nil {
				return fmt.Errorf("banpool.firewall.Ban(ip: %s) -> %w", ip, err)
			}
		}
	}
	return nil
}

func (f *firewall) Unban(ip string) error {
	if err := validateIP(ip); err != nil {
		return fmt.Errorf("banpool.firewall.Unban(ip: %s) -> %w", ip, err)
	}

	if !f.hasRule(ip) {
		return nil
	}

	switch f.fwEngine {
	case "iptables":
		for _, chain := range f.chains {
			if output, err := runCommand("iptables", "--delete", chain, "--source", ip, "--jump", "DROP"); err != nil {
				return fmt.Errorf("banpool.firewall.Unban(ip: %s) -> %w: %v: %s", ip, ErrCantUnbanIP, err, output)
			}
		}

	case "nftables":
		for _, chain := range f.chains {
			if err := f.deleteNftablesRule(chain, ip); err != nil {
				return err
			}
		}

	case "firewalld":
		for _, chain := range f.chains {
			if err := f.changeFirewalldRule(chain, "--remove-rich-rule", ip, ErrCantUnbanIP); err != nil {
				return fmt.Errorf("banpool.firewall.Unban(ip: %s) -> %w", ip, err)
			}
		}
	}

	return nil
}

func (f *firewall) deleteNftablesRule(chain, ip string) error {
	output, err := runCommand("nft", "-a", "list", "chain", "inet", "filter", chain)
	if err != nil {
		return fmt.Errorf("banpool.firewall.Unban(ip: %s) -> %w: %v: %s", ip, ErrCantUnbanIP, err, output)
	}

	for _, line := range strings.Split(string(output), "\n") {
		if !strings.Contains(line, fmt.Sprintf("ip saddr %s drop", ip)) {
			continue
		}
		parts := strings.Split(line, "# handle ")
		if len(parts) != 2 {
			continue
		}
		handle := strings.TrimSpace(parts[1])
		if output, err := runCommand("nft", "delete", "rule", "inet", "filter", chain, "handle", handle); err != nil {
			return fmt.Errorf("banpool.firewall.Unban(ip: %s) -> %w: %v: %s", ip, ErrCantUnbanIP, err, output)
		}
	}
	return nil
}

func (f *firewall) changeFirewalldRule(chain, operation, ip string, failure error) error {
	rule := fmt.Sprintf(`rule family="ipv4" source address="%s" drop`, ip)
	args := []string{operation, rule}
	if chain == dockerUserChain {
		args = []string{"--policy", firewalldDockerPolicy, operation, rule}
	} else if chain != "INPUT" {
		return fmt.Errorf("%w: unsupported firewalld chain %q", failure, chain)
	}

	if output, err := runCommand("firewall-cmd", args...); err != nil {
		return fmt.Errorf("%w: %v: %s", failure, err, output)
	}
	return nil
}

func (f *firewall) hasRule(ip string) bool {
	switch f.fwEngine {
	case "iptables":
		for _, chain := range f.chains {
			if _, err := runCommand("iptables", "--check", chain, "--source", ip, "--jump", "DROP"); err != nil {
				return false
			}
		}
		return true

	case "nftables":
		for _, chain := range f.chains {
			output, err := runCommand("nft", "-a", "list", "chain", "inet", "filter", chain)
			if err != nil || !strings.Contains(string(output), fmt.Sprintf("ip saddr %s drop", ip)) {
				return false
			}
		}
		return true

	case "firewalld":
		for _, chain := range f.chains {
			args := []string{"--query-rich-rule", fmt.Sprintf(`rule family="ipv4" source address="%s" drop`, ip)}
			if chain == dockerUserChain {
				args = []string{"--policy", firewalldDockerPolicy, "--query-rich-rule", fmt.Sprintf(`rule family="ipv4" source address="%s" drop`, ip)}
			} else if chain != "INPUT" {
				return false
			}
			if _, err := runCommand("firewall-cmd", args...); err != nil {
				return false
			}
		}
		return true
	}

	return false
}

func validateIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("%w: %s", ErrInvalidIP, ip)
	}

	return nil
}

func validateBanIP(ip string) error {
	if err := validateIP(ip); err != nil {
		return err
	}

	v4 := net.ParseIP(ip).To4()
	if v4 != nil && (v4[3] == 0 || v4[3] == 255) {
		return fmt.Errorf("%w: %s", ErrReservedIPv4Address, ip)
	}

	return nil
}
