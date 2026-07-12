package monitor

import "errors"

var (
	ErrCantConnectToDocker = errors.New("cant connect to docker")
	ErrEngineNotFound      = errors.New("engine not found or not exists")
)
