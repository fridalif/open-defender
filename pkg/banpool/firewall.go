package banpool

//go:generate mockgen -source=firewall.go -destination=mocks/firewall_mock.go -package=mocks

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
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
}

func NewFirewall(fwEngine string) Firewall {
	return &firewall{
		fwEngine: fwEngine,
	}
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
		if output, err := runCommand("iptables", "--insert", "INPUT", "--source", ip, "--jump", "DROP"); err != nil {
			return fmt.Errorf("banpool.firewall.Ban(ip: %s) -> %w: %v: %s", ip, ErrCantBanIP, err, output)
		}
	case "nftables":
		if output, err := runCommand("nft", "insert", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"); err != nil {
			return fmt.Errorf("banpool.firewall.Ban(ip: %s) -> %w: %v: %s", ip, ErrCantBanIP, err, output)
		}
	case "firewalld":
		if output, err := runCommand("firewall-cmd", "--add-rich-rule", fmt.Sprintf(`rule family="ipv4" source address="%s" drop`, ip)); err != nil {
			return fmt.Errorf("banpool.firewall.Ban(ip: %s) -> %w: %v: %s", ip, ErrCantBanIP, err, output)
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
		if output, err := runCommand("iptables", "--delete", "INPUT", "--source", ip, "--jump", "DROP"); err != nil {
			return fmt.Errorf("banpool.firewall.Unban(ip: %s) -> %w: %v: %s", ip, ErrCantUnbanIP, err, output)
		}

	case "nftables":
		output, err := runCommand("nft", "-a", "list", "chain", "inet", "filter", "input")
		if err != nil {
			return fmt.Errorf("banpool.firewall.Unban(ip: %s) -> %w: %v: %s", ip, ErrCantUnbanIP, err, output)
		}

		handle := ""
		rule := fmt.Sprintf("ip saddr %s drop", ip)

		for _, line := range strings.Split(string(output), "\n") {
			if !strings.Contains(line, rule) {
				continue
			}

			parts := strings.Split(line, "# handle ")
			if len(parts) == 2 {
				handle = strings.TrimSpace(parts[1])
				break
			}
		}

		if handle == "" {
			return nil
		}

		if output, err := runCommand("nft", "delete", "rule", "inet", "filter", "input", "handle", handle); err != nil {
			return fmt.Errorf("banpool.firewall.Unban(ip: %s) -> %w: %v: %s", ip, ErrCantUnbanIP, err, output)
		}

	case "firewalld":
		if output, err := runCommand(
			"firewall-cmd",
			"--remove-rich-rule",
			fmt.Sprintf(`rule family="ipv4" source address="%s" drop`, ip),
		); err != nil {
			return fmt.Errorf("banpool.firewall.Unban(ip: %s) -> %w: %v: %s", ip, ErrCantUnbanIP, err, output)
		}
	}

	return nil
}

func (f *firewall) hasRule(ip string) bool {
	switch f.fwEngine {
	case "iptables":
		_, err := runCommand("iptables", "--check", "INPUT", "--source", ip, "--jump", "DROP")
		return err == nil

	case "nftables":
		output, err := runCommand("nft", "-a", "list", "chain", "inet", "filter", "input")
		if err != nil {
			return false
		}

		return strings.Contains(
			string(output),
			fmt.Sprintf("ip saddr %s drop", ip),
		)

	case "firewalld":
		_, err := runCommand(
			"firewall-cmd",
			"--query-rich-rule",
			fmt.Sprintf(`rule family="ipv4" source address="%s" drop`, ip),
		)
		return err == nil
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
