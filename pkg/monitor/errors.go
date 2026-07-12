package monitor

import "errors"

var (
	ErrCantConnectToDocker = errors.New("cant connect to docker")
)
