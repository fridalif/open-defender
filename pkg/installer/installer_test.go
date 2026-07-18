package installer

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stubRunCommand(t *testing.T, fn func(name string, args ...string) ([]byte, error)) {
	t.Helper()
	original := runCommand
	runCommand = fn
	t.Cleanup(func() { runCommand = original })
}

func okRun(t *testing.T) *[]string {
	seen := &[]string{}
	stubRunCommand(t, func(name string, args ...string) ([]byte, error) {
		*seen = append(*seen, strings.Join(append([]string{name}, args...), " "))
		return nil, nil
	})
	return seen
}

func TestServiceNameAndBinaryPath(t *testing.T) {
	i := New()
	if i.ServiceName() != serviceName {
		t.Errorf("ServiceName() = %q", i.ServiceName())
	}
	if i.BinaryPath() != filepath.Join("/", "usr", "bin", serviceName) {
		t.Errorf("BinaryPath() = %q", i.BinaryPath())
	}
}

func TestStartStopRestart(t *testing.T) {
	seen := okRun(t)
	i := New()

	if err := i.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if err := i.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if err := i.Restart(); err != nil {
		t.Fatalf("Restart() error: %v", err)
	}

	want := []string{"systemctl start open-defender", "systemctl stop open-defender", "systemctl restart open-defender"}
	if strings.Join(*seen, "|") != strings.Join(want, "|") {
		t.Fatalf("commands = %v, want %v", *seen, want)
	}
}

func TestServiceCommandFailures(t *testing.T) {
	fail := func(string, ...string) ([]byte, error) { return []byte("boom"), errors.New("exit 1") }

	stubRunCommand(t, fail)
	if err := New().Start(); !errors.Is(err, ErrStartService) {
		t.Errorf("Start() error = %v, want ErrStartService", err)
	}
	if err := New().Stop(); !errors.Is(err, ErrStopService) {
		t.Errorf("Stop() error = %v, want ErrStopService", err)
	}
	if err := New().Restart(); !errors.Is(err, ErrRestartService) {
		t.Errorf("Restart() error = %v, want ErrRestartService", err)
	}
}

func stubExecutable(t *testing.T, path string, err error) {
	t.Helper()
	orig := osExecutable
	osExecutable = func() (string, error) { return path, err }
	t.Cleanup(func() { osExecutable = orig })
}

func stubEvalSymlinks(t *testing.T, fn func(string) (string, error)) {
	t.Helper()
	orig := evalSymlinks
	evalSymlinks = fn
	t.Cleanup(func() { evalSymlinks = orig })
}

func TestInstallBinary(t *testing.T) {
	t.Run("executable error", func(t *testing.T) {
		stubExecutable(t, "", errors.New("boom"))
		if err := (&installer{}).installBinary(); !errors.Is(err, ErrGettingExecutable) {
			t.Fatalf("error = %v, want ErrGettingExecutable", err)
		}
	})

	t.Run("eval symlinks error", func(t *testing.T) {
		stubEvalSymlinks(t, func(string) (string, error) { return "", errors.New("boom") })
		if err := (&installer{}).installBinary(); !errors.Is(err, ErrGettingExecutable) {
			t.Fatalf("error = %v, want ErrGettingExecutable", err)
		}
	})

	t.Run("already in place", func(t *testing.T) {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		exe, err = filepath.EvalSymlinks(exe)
		if err != nil {
			t.Fatal(err)
		}
		if err := (&installer{binaryPath: exe}).installBinary(); err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
	})

	t.Run("open executable error", func(t *testing.T) {
		stubExecutable(t, "/no/such/exe", nil)
		stubEvalSymlinks(t, func(s string) (string, error) { return s, nil })
		if err := (&installer{binaryPath: "/tmp/other"}).installBinary(); !errors.Is(err, ErrOpenExecutable) {
			t.Fatalf("error = %v, want ErrOpenExecutable", err)
		}
	})

	t.Run("mkdir error", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		i := &installer{binaryPath: filepath.Join(blocker, "sub", "bin")}
		if err := i.installBinary(); !errors.Is(err, ErrCreateBinaryDir) {
			t.Fatalf("error = %v, want ErrCreateBinaryDir", err)
		}
	})

	t.Run("remove error", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "target")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "inner"), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := (&installer{binaryPath: dir}).installBinary(); !errors.Is(err, ErrReplaceBinary) {
			t.Fatalf("error = %v, want ErrReplaceBinary", err)
		}
	})

	t.Run("open destination error", func(t *testing.T) {
		orig := openBinary
		openBinary = func(string, int, os.FileMode) (*os.File, error) { return nil, errors.New("boom") }
		t.Cleanup(func() { openBinary = orig })

		if err := (&installer{binaryPath: filepath.Join(t.TempDir(), "bin")}).installBinary(); !errors.Is(err, ErrWriteBinary) {
			t.Fatalf("error = %v, want ErrWriteBinary", err)
		}
	})

	t.Run("copy error", func(t *testing.T) {
		orig := copyBinary
		copyBinary = func(io.Writer, io.Reader) (int64, error) { return 0, errors.New("boom") }
		t.Cleanup(func() { copyBinary = orig })

		if err := (&installer{binaryPath: filepath.Join(t.TempDir(), "bin")}).installBinary(); !errors.Is(err, ErrWriteBinary) {
			t.Fatalf("error = %v, want ErrWriteBinary", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		i := &installer{binaryPath: filepath.Join(t.TempDir(), "bin", "open-defender")}
		if err := i.installBinary(); err != nil {
			t.Fatalf("error = %v", err)
		}
		if _, err := os.Stat(i.binaryPath); err != nil {
			t.Fatalf("binary not written: %v", err)
		}
	})
}

func TestInstallUnit(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		i := &installer{binaryPath: "/opt/open-defender", unitPath: filepath.Join(t.TempDir(), "od.service")}
		if err := i.installUnit(); err != nil {
			t.Fatalf("error = %v", err)
		}
		data, err := os.ReadFile(i.unitPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "ExecStart=/opt/open-defender") {
			t.Errorf("unit missing ExecStart:\n%s", data)
		}
	})

	t.Run("mkdir error", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := (&installer{unitPath: filepath.Join(blocker, "sub", "od.service")}).installUnit(); !errors.Is(err, ErrCreateUnitDir) {
			t.Fatalf("error = %v, want ErrCreateUnitDir", err)
		}
	})

	t.Run("write error", func(t *testing.T) {
		if err := (&installer{unitPath: t.TempDir()}).installUnit(); !errors.Is(err, ErrWriteUnit) {
			t.Fatalf("error = %v, want ErrWriteUnit", err)
		}
	})
}

func TestEnableService(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		okRun(t)
		if err := (&installer{}).enableService(); err != nil {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("failures", func(t *testing.T) {
		for _, failArg := range []string{"daemon-reload", "enable", "restart"} {
			failArg := failArg
			stubRunCommand(t, func(name string, args ...string) ([]byte, error) {
				for _, a := range args {
					if a == failArg {
						return []byte("boom"), errors.New("exit 1")
					}
				}
				return nil, nil
			})
			if err := (&installer{}).enableService(); err == nil {
				t.Fatalf("enableService() error = nil when %q fails", failArg)
			}
		}
	})
}

func TestInstall(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		okRun(t)
		dir := t.TempDir()
		i := &installer{
			binaryPath: filepath.Join(dir, "bin", "open-defender"),
			unitPath:   filepath.Join(dir, "unit", "open-defender.service"),
		}
		if err := i.Install(); err != nil {
			t.Fatalf("Install() error: %v", err)
		}
	})

	t.Run("install binary fails", func(t *testing.T) {
		stubExecutable(t, "", errors.New("boom"))
		if err := (&installer{}).Install(); !errors.Is(err, ErrGettingExecutable) {
			t.Fatalf("error = %v, want ErrGettingExecutable", err)
		}
	})

	t.Run("install unit fails", func(t *testing.T) {
		okRun(t)
		blocker := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		i := &installer{
			binaryPath: filepath.Join(t.TempDir(), "bin", "open-defender"),
			unitPath:   filepath.Join(blocker, "sub", "od.service"),
		}
		if err := i.Install(); !errors.Is(err, ErrCreateUnitDir) {
			t.Fatalf("error = %v, want ErrCreateUnitDir", err)
		}
	})

	t.Run("enable service fails", func(t *testing.T) {
		stubRunCommand(t, func(string, ...string) ([]byte, error) { return []byte("boom"), errors.New("exit 1") })
		dir := t.TempDir()
		i := &installer{
			binaryPath: filepath.Join(dir, "bin", "open-defender"),
			unitPath:   filepath.Join(dir, "unit", "open-defender.service"),
		}
		if err := i.Install(); !errors.Is(err, ErrDaemonReload) {
			t.Fatalf("error = %v, want ErrDaemonReload", err)
		}
	})
}
