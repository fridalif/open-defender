# Open Defender

![open-defender.jpg](./open-defender.webp)
Open Source Linux Servers complex tool for monitoring and security audit

Objectives:
- [x] Service Installation
- [x] SSH Monitor (AntiBrute)
- [x] Web Monitor (AntiRecon + AntiBrute)
- [x] Database Monitor (Antibrute)
- [x] Resource Monitor with top'ing proccesses in overloads
- [ ] eBPF Monitoring
    - [ ] Network Monitor (AntiRecon)
    - [ ] Command Execution (with block for definite users)
    - [ ] New Kernel Modules (with block)
    - [ ] New Crontabs (with block)
    - [ ] New Services (with block)
    - [ ] New Records in .*rc, .profile and other
- [ ] ...
- [ ] Security Audit Mode
    - [ ] Weak Configs
    - [ ] Weak Passwords
    - [ ]  ...

## Usage

```
Usage: open-defender [options]

Options:
  -i, --install    install open-defender as a systemd service and start it
  -u, --update     update the installed binary from the latest github release
  -t, --test       check the current config and exit
  -r, --restart    restart the open-defender service
  -h, --help       print this message
```


### Checking the config (`-t`)

Reads `/etc/open-defender/config.yaml`, reports every problem it finds at once and exits with a
non-zero status when there is any. The config is only read, never rewritten, so it is safe to run
against a live installation:

```sh
open-defender -t
```

It catches an unknown `mode` or `engine`, a `pattern` that does not compile or that has no
`(?P<ip>...)` group, a `log_path` that cannot be read, a missing `unit_name`, a zero `tries`,
`window_seconds` or `ban_seconds`, a `warning` limit above its `alert`, and an address in
`ip_whitelist` that is not an address. A monitor left `disabled` is skipped, as it is never started.

### Updating (`-u`)

```sh
sudo open-defender -u
```

The latest version is taken from [version.txt](./version.txt) of the repository and the
architecture from the running binary (`amd64`, `386`, `arm64`, `arm32`); both are offered as a
suggestion that an empty line accepts and anything typed overrides. Should either of them fail to be
worked out, it is asked for outright.

The release is then fetched from
`https://github.com/fridalif/open-defender/releases/download/<version>/open-defender_<arch>`,
the service is stopped, the binary at `/usr/bin/open-defender` is swapped and the service is started
back. The download happens before the service is stopped, and the previous binary is kept aside and
put back should the new one fail to start.

### Restarting (`-r`)

```sh
sudo open-defender -r
```

## Building

Requires Go 1.25+ and a C compiler (`gcc`), since the SQLite driver is a cgo package.

Build the binary into `build/open-defender`:

```sh
make build
```

### Tests

```sh
make test          # run all tests
make test-verbose  # same, with per-test output
make test-race     # run tests under the race detector
make cover         # run tests and print a per-function coverage report
make cover-html    # same, then open the coverage report in a browser
make vet           # run go vet
make check         # go vet + tests
make clean         # remove build artifacts and drop the test cache
```
