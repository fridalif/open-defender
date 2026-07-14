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
	ErrConfigNotFound           = errors.New("config file does not exist")
)

var (
	ErrInvalidConfig      = errors.New("config is invalid")
	ErrEmptyValue         = errors.New("must not be empty")
	ErrZeroValue          = errors.New("must not be zero")
	ErrInvalidValue       = errors.New("unexpected value")
	ErrInvalidIP          = errors.New("not an ip address")
	ErrInvalidPattern     = errors.New("failed to compile pattern")
	ErrMissingIPGroup     = errors.New("pattern has no named ip group")
	ErrLogFileNotReadable = errors.New("log file cannot be read")
	ErrWarningAboveAlert  = errors.New("warning limit is above the alert limit")
	ErrNoLimitsSet        = errors.New("no limits are set")
)
