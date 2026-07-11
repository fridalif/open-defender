package config

import "errors"

var (
	ErrCreateConfigDir          = errors.New("failed to create config directory")
	ErrMarshalConfig            = errors.New("failed to marshal config")
	ErrWriteConfig              = errors.New("failed to write config file")
	ErrStatConfig               = errors.New("failed to stat config file")
	ErrReadConfig               = errors.New("failed to read config file")
	ErrParseConfig              = errors.New("failed to parse config file")
	ErrGettingNetworkInterfaces = errors.New("failed to get network interfaces")
	ErrUnknownArgument          = errors.New("unknown argument")
)
