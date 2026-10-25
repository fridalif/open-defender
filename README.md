# Open Defender

![coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/fridalif/7fa26c09b8c489d79bbbaf8d53726345/raw/open-defender-coverage.json)

![open-defender.jpg](./open-defender.webp)

Open Source Linux Servers complex tool for monitoring and security audit

Optionally, the agent can export its events to **Light Defender Dashboard** over an end-to-end
encrypted WebSocket connection: one place for the events of every server instead of a login on each
of them. This is off by default and never required. Without the `exporter` section in
`config.yaml` the agent runs completely on its own and connects nowhere, and even with it turned on
an unreachable dashboard never holds up detection or banning. The protocol is documented in
[CLIENT.md](./CLIENT.md), the product pages are at
[light-defender.ru/open-defender](https://light-defender.ru/open-defender).

Objectives:
- [x] Service Installation
- [x] SSH Monitor (AntiBrute)
- [x] Web Monitor (AntiRecon + AntiBrute)
- [x] Database Monitor (Antibrute)
- [x] Resource Monitor with top'ing proccesses in overloads
- [ ] eBPF Monitoring
    - [x] Network Monitor (AntiRecon)
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

## Installation

### Quick install

Fetch the latest release for your architecture into `/usr/bin/open-defender`:

```sh
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)        ARCH=amd64 ;;
  i386|i686)     ARCH=386 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv6l) ARCH=arm32 ;;
  *) echo "Unknown architecture: $ARCH"; exit 1 ;;
esac
sudo curl -L -o /usr/bin/open-defender \
  https://github.com/fridalif/open-defender/releases/latest/download/open-defender_$ARCH
sudo chmod +x /usr/bin/open-defender
```

Then install it as a systemd service and start it:

```sh
sudo open-defender -i
```

The service reads `/etc/open-defender/config.yaml`; check it with `-t` and see the active monitors
with `-s` (see [Usage](#usage) below). Later releases are picked up with `sudo open-defender -u`.

## Usage

```
Usage: open-defender [options]

Options:
  -i, --install    install open-defender as a systemd service and start it
  -u, --update     update the installed binary from the latest github release
  -t, --test       check the current config and exit
  -s, --status     print the monitors that are turned on and exit
  -r, --restart    restart the open-defender service
  -h, --help       print this message
```

Neither `-t`, `-s` nor `-h` needs root, the rest do.

### The monitors that are turned on (`-s`)

```sh
open-defender -s
```

```
/etc/open-defender/config.yaml

MONITOR           MODE     ENGINE   SOURCE                   TRIES
ssh_monitor       blocker  syslog   /var/log/auth.log        5 in 300s, ban 900s
database_monitor  logger   journal  postgresql               5 in 300s
resource_monitor  enabled  -        /var/log/open-defender/  cpu 60/90, ram 60/90

disabled: web_recon_monitor, web_brute_monitor
```

A monitor left at `mode: disabled` is never started, so it is only named at the bottom. `SOURCE` is
the log file of the `syslog` engine or the unit of the `journal` and `docker` ones. The limits of the
resource monitor are printed as `warning/alert`, the ones left at zero are turned off and are left
out. Like `-t`, the config is only read, never rewritten.


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

## Command execution control

`ebpf_monitors.user_command_controller` checks execution attempts through BPF LSM (`bprm_check_security`). It requires Linux with BTF and active BPF LSM, and the agent must run as root in the initial host user namespace. Controller startup or update errors are logged and detach the controller; other monitors continue running.

```yaml
ebpf_monitors:
  user_command_controller:
    mode: logger
    block_type: positive
    target_users_ids: ["1000"]
    target_commands: ["curl", "wget"]
```

- `mode`: `disabled`, `logger`, or `blocker`. Omitting the section disables the controller, including on configuration reload.
- User IDs refer to the process user namespace. Commands match executable basenames, up to 63 bytes; configured paths are reduced to basenames. Shell builtins without a separate exec are not monitored.
- When both lists are set, both the user and command must match. An empty list imposes no condition on that criterion; two empty lists match nothing.
- `positive` selects list matches; `negative` selects everything except those matches. With two empty lists, `negative` selects all attempts except the unconditional exclusions below.
- `logger` permits selected attempts and reports **Critical (4)** events. These are execution attempts, without confirmation of successful execution. `blocker` denies selected attempts with `EPERM` and reports **High (3)** events. Other attempts are not reported.

**Root is always excluded and never reported:** real or effective UID 0 on the host or inside a container user namespace bypasses the policy regardless of configuration. Listing UID 0 does not override this exclusion.

Unknown user or mount namespaces permit all attempts without events. Discovery runs before attachment and then every 150 seconds, without overlapping scans. Each newly discovered namespace receives another 150 seconds for setup before policy is enabled, including namespaces present at agent startup. Each Docker container has a separate mount namespace, so it receives its own grace period even when sharing the host user namespace. Enforcement starts only when both namespaces are ready. Namespace descriptors remain pinned during the grace period and enforcement to prevent inode reuse. A nonempty UID map without UID 0 still receives policy for its other users; an uninitialized empty map remains unrestricted until discovery reads its final mapping. Root is always excluded.

On a test Linux host with BPF LSM and user namespace support, check unknown namespaces, blocking, logger events, and container root mapped to a nonzero host UID:

```sh
sudo go test -tags integration ./pkg/ebpfmonitors -run '^TestCommandControllerLSM

The messages the agent exchanges with the exporter endpoint over WebSocket, the envelope format,
the encryption and every operation are documented in [CLIENT.md](./CLIENT.md).

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
 -v
```

The integration tests activate policy only for their private user namespaces. Compilation alone does not verify kernel loading or LSM behavior.

## Agent protocol

The messages the agent exchanges with the exporter endpoint over WebSocket, the envelope format,
the encryption and every operation are documented in [CLIENT.md](./CLIENT.md).

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
