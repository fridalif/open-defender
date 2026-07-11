package installer

import "errors"

var (
	ErrGettingExecutable = errors.New("failed to get current executable path")
	ErrOpenExecutable    = errors.New("failed to open current executable")
	ErrCreateBinaryDir   = errors.New("failed to create binary directory")
	ErrReplaceBinary     = errors.New("failed to replace installed binary")
	ErrWriteBinary       = errors.New("failed to write binary")
	ErrCreateUnitDir     = errors.New("failed to create systemd unit directory")
	ErrWriteUnit         = errors.New("failed to write systemd unit file")
	ErrDaemonReload      = errors.New("failed to reload systemd daemon")
	ErrEnableService     = errors.New("failed to enable systemd service")
	ErrStartService      = errors.New("failed to start systemd service")
)
