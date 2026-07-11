package config

type BaseFields struct {
	Mode          string `json:"mode"` // disabled, logger, blocker
	LogPath       string `yaml:"log_path"`
	Tries         uint64 `yaml:"tries"`
	WindowSeconds uint64 `yaml:"window_seconds"`
	BanSeconds    uint64 `yaml:"ban_seconds"`
	Pattern       uint64 `yaml:"pattern"`
}

type SSHMonitorConfig struct {
	BaseFields
}
