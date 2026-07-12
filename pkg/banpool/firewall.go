package banpool

import (
	"fmt"
	"net"
	"os/exec"
)

const iptablesCommand = "iptables"

type Firewall interface {
	Ban(ip string) error
	Unban(ip string) error
}

type firewall struct{}

func NewFirewall() Firewall {
	return &firewall{}
}

func (f *firewall) Ban(ip string) error {
	if err := validateIP(ip); err != nil {
		return fmt.Errorf("banpool.firewall.Ban(ip: %s) -> %w", ip, err)
	}

	if f.hasRule(ip) {
		return nil
	}

	if output, err := exec.Command(iptablesCommand, "--insert", "INPUT", "--source", ip, "--jump", "DROP").CombinedOutput(); err != nil {
		return fmt.Errorf("banpool.firewall.Ban(ip: %s) -> %w: %v: %s", ip, ErrCantBanIP, err, output)
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

	if output, err := exec.Command(iptablesCommand, "--delete", "INPUT", "--source", ip, "--jump", "DROP").CombinedOutput(); err != nil {
		return fmt.Errorf("banpool.firewall.Unban(ip: %s) -> %w: %v: %s", ip, ErrCantUnbanIP, err, output)
	}

	return nil
}

func (f *firewall) hasRule(ip string) bool {
	err := exec.Command(iptablesCommand, "--check", "INPUT", "--source", ip, "--jump", "DROP").Run()
	return err == nil
}

func validateIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("%w: %s", ErrInvalidIP, ip)
	}

	return nil
}
