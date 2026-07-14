package config

import "fmt"

const Usage = `Usage: open-defender [options]

Options:
  -i, --install    install open-defender as a systemd service and start it
  -u, --update     update the installed binary from the latest github release
  -t, --test       check the current config and exit
  -r, --restart    restart the open-defender service
  -h, --help       print this message
`

type RunConfig struct {
	Install bool
	Update  bool
	Test    bool
	Restart bool
	Help    bool
}

func ParseArgs(argv []string) (*RunConfig, error) {
	runConfig := &RunConfig{}

	for _, arg := range argv[1:] {
		switch arg {
		case "-i", "--install":
			runConfig.Install = true
		case "-u", "--update":
			runConfig.Update = true
		case "-t", "--test":
			runConfig.Test = true
		case "-r", "--restart":
			runConfig.Restart = true
		case "-h", "--help":
			runConfig.Help = true
		default:
			return nil, fmt.Errorf("config.ParseArgs() -> %w: %s", ErrUnknownArgument, arg)
		}
	}

	return runConfig, nil
}
