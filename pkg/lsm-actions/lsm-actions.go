package lsmactions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type LSMActionsI interface {
	CheckIsActive() (bool, error)
	overrideGRUB() error
	updateGRUB() error
	getGRUBCmdlineLinuxDefault() (string, error)
	restartSystem() error
	Dialog() error
}

type lsmActions struct {
}

func NewLSMActions() LSMActionsI {
	return &lsmActions{}
}

func (la *lsmActions) Dialog() error {
	return nil
}

func (la *lsmActions) CheckIsActive() (bool, error) {
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false, err
	}
	return strings.Contains(string(data), "bpf"), nil
}

func (la *lsmActions) getGRUBCmdlineLinuxDefault() (string, error) {
	const (
		grubConfig = "/etc/default/grub"
		dropInDir  = "/etc/default/grub.d"
		key        = "GRUB_CMDLINE_LINUX_DEFAULT="
	)
	files := []string{grubConfig}
	entries, err := os.ReadDir(dropInDir)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("read %s: %w", dropInDir, err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".cfg") {
			files = append(files, filepath.Join(dropInDir, entry.Name()))
		}
	}

	var commandLine string
	found := false
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			return commandLine, fmt.Errorf("read %s: %w", file, err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			value := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), key))
			if !strings.HasPrefix(strings.TrimSpace(line), key) {
				continue
			}
			if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
				return commandLine, fmt.Errorf("%s in %s must use a double-quoted value", key, file)
			}
			commandLine = value[1 : len(value)-1]
			found = true
		}
	}
	if !found {
		return commandLine, fmt.Errorf("%s not found in %s or %s", key, grubConfig, dropInDir)
	}
	return commandLine, nil
}

func (la *lsmActions) overrideGRUB() error {
	return nil
}

func (la *lsmActions) updateGRUB() error {
	return nil
}

func (la *lsmActions) restartSystem() error {
	return nil
}
