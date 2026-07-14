package installer

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
)

const serviceName = "open-defender"

const unitTemplate = `[Unit]
Description=Open Defender
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`

type Installer interface {
	Install() error
	ServiceName() string
	BinaryPath() string
	Start() error
	Stop() error
	Restart() error
}

type installer struct {
	binaryPath string
	unitPath   string
}

func New() Installer {
	return &installer{
		binaryPath: path.Join("/", "usr", "bin", serviceName),
		unitPath:   path.Join("/", "etc", "systemd", "system", serviceName+".service"),
	}
}

func (i *installer) ServiceName() string {
	return serviceName
}

func (i *installer) BinaryPath() string {
	return i.binaryPath
}

func (i *installer) Start() error {
	if output, err := exec.Command("systemctl", "start", serviceName).CombinedOutput(); err != nil {
		return fmt.Errorf("installer.Start() -> %w: %v: %s", ErrStartService, err, output)
	}

	return nil
}

func (i *installer) Stop() error {
	if output, err := exec.Command("systemctl", "stop", serviceName).CombinedOutput(); err != nil {
		return fmt.Errorf("installer.Stop() -> %w: %v: %s", ErrStopService, err, output)
	}

	return nil
}

func (i *installer) Restart() error {
	if output, err := exec.Command("systemctl", "restart", serviceName).CombinedOutput(); err != nil {
		return fmt.Errorf("installer.Restart() -> %w: %v: %s", ErrRestartService, err, output)
	}

	return nil
}

func (i *installer) Install() error {
	if err := i.installBinary(); err != nil {
		return fmt.Errorf("installer.Install() -> %w", err)
	}

	if err := i.installUnit(); err != nil {
		return fmt.Errorf("installer.Install() -> %w", err)
	}

	if err := i.enableService(); err != nil {
		return fmt.Errorf("installer.Install() -> %w", err)
	}

	return nil
}

func (i *installer) installBinary() error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("installer.installBinary() -> %w: %v", ErrGettingExecutable, err)
	}

	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return fmt.Errorf("installer.installBinary() -> %w: %v", ErrGettingExecutable, err)
	}

	if executable == i.binaryPath {
		return nil
	}

	source, err := os.Open(executable)
	if err != nil {
		return fmt.Errorf("installer.installBinary() -> %w: %v", ErrOpenExecutable, err)
	}
	defer source.Close()

	if err := os.MkdirAll(filepath.Dir(i.binaryPath), 0755); err != nil {
		return fmt.Errorf("installer.installBinary() -> %w: %v", ErrCreateBinaryDir, err)
	}

	if err := os.Remove(i.binaryPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("installer.installBinary() -> %w: %v", ErrReplaceBinary, err)
	}

	destination, err := os.OpenFile(i.binaryPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("installer.installBinary() -> %w: %v", ErrWriteBinary, err)
	}
	defer destination.Close()

	if _, err := io.Copy(destination, source); err != nil {
		return fmt.Errorf("installer.installBinary() -> %w: %v", ErrWriteBinary, err)
	}

	return nil
}

func (i *installer) installUnit() error {
	if err := os.MkdirAll(filepath.Dir(i.unitPath), 0755); err != nil {
		return fmt.Errorf("installer.installUnit() -> %w: %v", ErrCreateUnitDir, err)
	}

	unit := fmt.Sprintf(unitTemplate, i.binaryPath)

	if err := os.WriteFile(i.unitPath, []byte(unit), 0644); err != nil {
		return fmt.Errorf("installer.installUnit() -> %w: %v", ErrWriteUnit, err)
	}

	return nil
}

func (i *installer) enableService() error {
	if output, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("installer.enableService() -> %w: %v: %s", ErrDaemonReload, err, output)
	}

	if output, err := exec.Command("systemctl", "enable", serviceName).CombinedOutput(); err != nil {
		return fmt.Errorf("installer.enableService() -> %w: %v: %s", ErrEnableService, err, output)
	}

	if err := i.Restart(); err != nil {
		return fmt.Errorf("installer.enableService() -> %w", err)
	}

	return nil
}
