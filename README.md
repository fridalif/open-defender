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
