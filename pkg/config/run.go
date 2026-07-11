package config

import "fmt"

const Usage = `Usage: open-defender [options]

Options:
  -i, --install    install open-defender as a systemd service and start it
  -h, --help       print this message
`

type RunConfig struct {
	Install bool
	Help    bool
}

func ParseArgs(argv []string) (*RunConfig, error) {
	runConfig := &RunConfig{}

	for _, arg := range argv[1:] {
		switch arg {
		case "-i", "--install":
			runConfig.Install = true
		case "-h", "--help":
			runConfig.Help = true
		default:
			return nil, fmt.Errorf("config.ParseArgs() -> %w: %s", ErrUnknownArgument, arg)
		}
	}

	return runConfig, nil
}
