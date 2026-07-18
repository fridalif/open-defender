package updater

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"open-defender/pkg/installer"
	"open-defender/pkg/installer/mocks"

	"go.uber.org/mock/gomock"
)

func newUpdater(input string, svc *mocks.MockInstaller) *updater {
	return &updater{
		svc:    svc,
		in:     bufio.NewReader(strings.NewReader(input)),
		out:    io.Discard,
		client: http.DefaultClient,
	}
}

func withVersionURL(t *testing.T, url string) {
	t.Helper()
	original := versionURL
	versionURL = url
	t.Cleanup(func() { versionURL = original })
}

func withReleaseURL(t *testing.T, url string) {
	t.Helper()
	original := releaseURL
	releaseURL = url
	t.Cleanup(func() { releaseURL = original })
}

func withGoArch(t *testing.T, arch string) {
	t.Helper()
	original := goArch
	goArch = arch
	t.Cleanup(func() { goArch = original })
}

func stubRename(t *testing.T, fn func(src, dst string) error) {
	t.Helper()
	original := renameFile
	renameFile = fn
	t.Cleanup(func() { renameFile = original })
}

func serve(t *testing.T, status int, body string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestNew(t *testing.T) {
	if New(installer.New()) == nil {
		t.Fatal("New() returned nil")
	}
}

func TestVersionPattern(t *testing.T) {
	for _, v := range []string{"1.2.3", "v1.0", "release_2024", "a-b-c"} {
		if !versionPattern.MatchString(v) {
			t.Errorf("rejected valid %q", v)
		}
	}
	for _, v := range []string{"1.2 3", "bad/slash", "", "semi;colon"} {
		if versionPattern.MatchString(v) {
			t.Errorf("accepted invalid %q", v)
		}
	}
}

func TestDetectArch(t *testing.T) {
	cases := map[string]string{"amd64": "amd64", "386": "386", "arm64": "arm64", "arm": "arm32"}
	for goarch, want := range cases {
		withGoArch(t, goarch)
		got, err := (&updater{}).detectArch()
		if err != nil || got != want {
			t.Fatalf("detectArch(%s) = %q, %v; want %q", goarch, got, err, want)
		}
	}

	withGoArch(t, "sparc")
	if _, err := (&updater{}).detectArch(); !errors.Is(err, ErrUnknownArch) {
		t.Fatalf("detectArch(sparc) error = %v, want ErrUnknownArch", err)
	}
}

func TestAsk(t *testing.T) {
	if got, _ := newUpdater("\n", nil).ask("v", "def"); got != "def" {
		t.Errorf("ask empty input = %q, want def", got)
	}
	if got, _ := newUpdater("typed\n", nil).ask("v", "def"); got != "typed" {
		t.Errorf("ask typed = %q, want typed", got)
	}
	if got, _ := newUpdater("typed\n", nil).ask("v", ""); got != "typed" {
		t.Errorf("ask no suggestion = %q, want typed", got)
	}
	if _, err := newUpdater("", nil).ask("v", ""); !errors.Is(err, ErrReadInput) {
		t.Errorf("ask EOF error = %v, want ErrReadInput", err)
	}
}

func TestResolveArch(t *testing.T) {
	if got, err := newUpdater("arm64\n", nil).resolveArch(); err != nil || got != "arm64" {
		t.Fatalf("resolveArch() = %q, %v; want arm64", got, err)
	}
	if _, err := newUpdater("sparc\n", nil).resolveArch(); !errors.Is(err, ErrUnknownArch) {
		t.Fatalf("resolveArch(sparc) error = %v, want ErrUnknownArch", err)
	}
	if _, err := newUpdater("", nil).resolveArch(); !errors.Is(err, ErrReadInput) {
		t.Fatalf("resolveArch(EOF) error = %v, want ErrReadInput", err)
	}

	withGoArch(t, "sparc")
	if got, err := newUpdater("arm64\n", nil).resolveArch(); err != nil || got != "arm64" {
		t.Fatalf("resolveArch(detect fails) = %q, %v; want arm64", got, err)
	}
}

func TestResolveVersion(t *testing.T) {
	t.Run("fetched suggestion", func(t *testing.T) {
		withVersionURL(t, serve(t, 200, "9.9.9").URL)
		if got, err := newUpdater("\n", nil).resolveVersion(); err != nil || got != "9.9.9" {
			t.Fatalf("resolveVersion() = %q, %v; want 9.9.9", got, err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		withVersionURL(t, "http://127.0.0.1:0")
		if _, err := newUpdater("bad!!\n", nil).resolveVersion(); !errors.Is(err, ErrInvalidVersion) {
			t.Fatalf("error = %v, want ErrInvalidVersion", err)
		}
	})
	t.Run("empty", func(t *testing.T) {
		withVersionURL(t, "http://127.0.0.1:0")
		if _, err := newUpdater("\n", nil).resolveVersion(); !errors.Is(err, ErrEmptyVersion) {
			t.Fatalf("error = %v, want ErrEmptyVersion", err)
		}
	})
	t.Run("ask error", func(t *testing.T) {
		withVersionURL(t, "http://127.0.0.1:0")
		if _, err := newUpdater("", nil).resolveVersion(); !errors.Is(err, ErrReadInput) {
			t.Fatalf("error = %v, want ErrReadInput", err)
		}
	})
}

func TestFetchVersion(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		withVersionURL(t, serve(t, 200, "1.2.3\n").URL)
		if got, err := (&updater{}).fetchVersion(); err != nil || got != "1.2.3" {
			t.Fatalf("fetchVersion() = %q, %v", got, err)
		}
	})
	t.Run("get error", func(t *testing.T) {
		withVersionURL(t, "://bad")
		if _, err := (&updater{}).fetchVersion(); !errors.Is(err, ErrFetchVersion) {
			t.Fatalf("error = %v, want ErrFetchVersion", err)
		}
	})
	t.Run("non 200", func(t *testing.T) {
		withVersionURL(t, serve(t, 500, "").URL)
		if _, err := (&updater{}).fetchVersion(); !errors.Is(err, ErrFetchVersion) {
			t.Fatalf("error = %v, want ErrFetchVersion", err)
		}
	})
	t.Run("empty", func(t *testing.T) {
		withVersionURL(t, serve(t, 200, "  ").URL)
		if _, err := (&updater{}).fetchVersion(); !errors.Is(err, ErrFetchVersion) {
			t.Fatalf("error = %v, want ErrFetchVersion", err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		withVersionURL(t, serve(t, 200, "not valid!!").URL)
		if _, err := (&updater{}).fetchVersion(); !errors.Is(err, ErrInvalidVersion) {
			t.Fatalf("error = %v, want ErrInvalidVersion", err)
		}
	})
	t.Run("read error", func(t *testing.T) {
		original := readAll
		readAll = func(io.Reader) ([]byte, error) { return nil, errors.New("boom") }
		t.Cleanup(func() { readAll = original })
		withVersionURL(t, serve(t, 200, "1.2.3").URL)
		if _, err := (&updater{}).fetchVersion(); !errors.Is(err, ErrFetchVersion) {
			t.Fatalf("error = %v, want ErrFetchVersion", err)
		}
	})
}

func TestDownload(t *testing.T) {
	binaryPathMock := func(t *testing.T, path string) *mocks.MockInstaller {
		ctrl := gomock.NewController(t)
		svc := mocks.NewMockInstaller(ctrl)
		svc.EXPECT().BinaryPath().Return(path).AnyTimes()
		return svc
	}

	t.Run("success", func(t *testing.T) {
		server := serve(t, 200, "binary-bytes")
		u := newUpdater("", binaryPathMock(t, filepath.Join(t.TempDir(), "open-defender")))
		path, err := u.download(server.URL)
		if err != nil {
			t.Fatalf("download() error: %v", err)
		}
		defer os.Remove(path)
		data, _ := os.ReadFile(path)
		if string(data) != "binary-bytes" {
			t.Errorf("content = %q", data)
		}
	})

	t.Run("not found", func(t *testing.T) {
		server := serve(t, 404, "")
		u := newUpdater("", binaryPathMock(t, filepath.Join(t.TempDir(), "open-defender")))
		if _, err := u.download(server.URL); !errors.Is(err, ErrReleaseNotFound) {
			t.Fatalf("error = %v, want ErrReleaseNotFound", err)
		}
	})

	t.Run("other status", func(t *testing.T) {
		server := serve(t, 500, "")
		u := newUpdater("", binaryPathMock(t, filepath.Join(t.TempDir(), "open-defender")))
		if _, err := u.download(server.URL); !errors.Is(err, ErrDownloadRelease) {
			t.Fatalf("error = %v, want ErrDownloadRelease", err)
		}
	})

	t.Run("get error", func(t *testing.T) {
		u := newUpdater("", binaryPathMock(t, filepath.Join(t.TempDir(), "open-defender")))
		if _, err := u.download("://bad"); !errors.Is(err, ErrDownloadRelease) {
			t.Fatalf("error = %v, want ErrDownloadRelease", err)
		}
	})

	t.Run("mkdir error", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "file")
		os.WriteFile(blocker, []byte("x"), 0644)
		server := serve(t, 200, "x")
		u := newUpdater("", binaryPathMock(t, filepath.Join(blocker, "sub", "bin")))
		if _, err := u.download(server.URL); !errors.Is(err, ErrWriteBinary) {
			t.Fatalf("error = %v, want ErrWriteBinary", err)
		}
	})

	t.Run("create temp error", func(t *testing.T) {
		original := createTemp
		createTemp = func(string, string) (*os.File, error) { return nil, errors.New("boom") }
		t.Cleanup(func() { createTemp = original })
		server := serve(t, 200, "x")
		u := newUpdater("", binaryPathMock(t, filepath.Join(t.TempDir(), "open-defender")))
		if _, err := u.download(server.URL); !errors.Is(err, ErrWriteBinary) {
			t.Fatalf("error = %v, want ErrWriteBinary", err)
		}
	})

	t.Run("copy error", func(t *testing.T) {
		original := copyFile
		copyFile = func(io.Writer, io.Reader) (int64, error) { return 0, errors.New("boom") }
		t.Cleanup(func() { copyFile = original })
		server := serve(t, 200, "x")
		u := newUpdater("", binaryPathMock(t, filepath.Join(t.TempDir(), "open-defender")))
		if _, err := u.download(server.URL); !errors.Is(err, ErrWriteBinary) {
			t.Fatalf("error = %v, want ErrWriteBinary", err)
		}
	})

	t.Run("chmod error", func(t *testing.T) {
		original := chmodFile
		chmodFile = func(string, os.FileMode) error { return errors.New("boom") }
		t.Cleanup(func() { chmodFile = original })
		server := serve(t, 200, "x")
		u := newUpdater("", binaryPathMock(t, filepath.Join(t.TempDir(), "open-defender")))
		if _, err := u.download(server.URL); !errors.Is(err, ErrWriteBinary) {
			t.Fatalf("error = %v, want ErrWriteBinary", err)
		}
	})
}

func swapUpdater(t *testing.T, target string) (*updater, *mocks.MockInstaller) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockInstaller(ctrl)
	svc.EXPECT().BinaryPath().Return(target).AnyTimes()
	return &updater{svc: svc}, svc
}

func TestSwapBinary(t *testing.T) {
	t.Run("success target exists", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "open-defender")
		os.WriteFile(target, []byte("old"), 0755)
		downloaded := filepath.Join(dir, "new")
		os.WriteFile(downloaded, []byte("new"), 0755)

		u, svc := swapUpdater(t, target)
		svc.EXPECT().Stop().Return(nil)
		svc.EXPECT().Start().Return(nil)

		if err := u.swapBinary(downloaded); err != nil {
			t.Fatalf("error: %v", err)
		}
		if data, _ := os.ReadFile(target); string(data) != "new" {
			t.Errorf("target = %q, want new", data)
		}
	})

	t.Run("success target absent", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "open-defender")
		downloaded := filepath.Join(dir, "new")
		os.WriteFile(downloaded, []byte("new"), 0755)

		u, svc := swapUpdater(t, target)
		svc.EXPECT().Stop().Return(nil)
		svc.EXPECT().Start().Return(nil)

		if err := u.swapBinary(downloaded); err != nil {
			t.Fatalf("error: %v", err)
		}
	})

	t.Run("stop error", func(t *testing.T) {
		u, svc := swapUpdater(t, filepath.Join(t.TempDir(), "open-defender"))
		svc.EXPECT().Stop().Return(errors.New("boom"))
		if err := u.swapBinary("x"); err == nil {
			t.Fatal("error = nil, want stop failure")
		}
	})

	t.Run("backup rename error", func(t *testing.T) {
		u, svc := swapUpdater(t, "/target")
		svc.EXPECT().Stop().Return(nil)
		stubRename(t, func(src, dst string) error { return errors.New("boom") })
		if err := u.swapBinary("x"); !errors.Is(err, ErrReplaceBinary) {
			t.Fatalf("error = %v, want ErrReplaceBinary", err)
		}
	})

	t.Run("swap fails with restore", func(t *testing.T) {
		u, svc := swapUpdater(t, "/target")
		svc.EXPECT().Stop().Return(nil)
		svc.EXPECT().Start().Return(nil)
		stubRename(t, func(src, dst string) error {
			if src == "/downloaded" {
				return errors.New("boom")
			}
			return nil
		})
		if err := u.swapBinary("/downloaded"); !errors.Is(err, ErrReplaceBinary) {
			t.Fatalf("error = %v, want ErrReplaceBinary", err)
		}
	})

	t.Run("swap fails restore ok start logs", func(t *testing.T) {
		u, svc := swapUpdater(t, "/target")
		svc.EXPECT().Stop().Return(nil)
		svc.EXPECT().Start().Return(errors.New("boom"))
		stubRename(t, func(src, dst string) error {
			if src == "/downloaded" {
				return errors.New("boom")
			}
			return nil
		})
		if err := u.swapBinary("/downloaded"); !errors.Is(err, ErrReplaceBinary) {
			t.Fatalf("error = %v, want ErrReplaceBinary", err)
		}
	})

	t.Run("swap fails restore fails", func(t *testing.T) {
		u, svc := swapUpdater(t, "/target")
		svc.EXPECT().Stop().Return(nil)
		stubRename(t, func(src, dst string) error {
			if src == "/target.bak" || src == "/downloaded" {
				return errors.New("boom")
			}
			return nil
		})
		if err := u.swapBinary("/downloaded"); !errors.Is(err, ErrReplaceBinary) {
			t.Fatalf("error = %v, want ErrReplaceBinary", err)
		}
	})

	t.Run("swap fails no restore", func(t *testing.T) {
		u, svc := swapUpdater(t, "/target")
		svc.EXPECT().Stop().Return(nil)
		stubRename(t, func(src, dst string) error {
			if src == "/target" {
				return os.ErrNotExist
			}
			return errors.New("boom")
		})
		if err := u.swapBinary("/downloaded"); !errors.Is(err, ErrReplaceBinary) {
			t.Fatalf("error = %v, want ErrReplaceBinary", err)
		}
	})

	t.Run("start fails no restore", func(t *testing.T) {
		u, svc := swapUpdater(t, "/target")
		svc.EXPECT().Stop().Return(nil)
		svc.EXPECT().Start().Return(errors.New("boom"))
		stubRename(t, func(src, dst string) error {
			if src == "/target" {
				return os.ErrNotExist
			}
			return nil
		})
		if err := u.swapBinary("/downloaded"); err == nil {
			t.Fatal("error = nil, want start failure")
		}
	})

	t.Run("start fails restore succeeds", func(t *testing.T) {
		u, svc := swapUpdater(t, "/target")
		svc.EXPECT().Stop().Return(nil)
		gomock.InOrder(
			svc.EXPECT().Start().Return(errors.New("boom")),
			svc.EXPECT().Start().Return(nil),
		)
		stubRename(t, func(src, dst string) error { return nil })
		if err := u.swapBinary("/downloaded"); err == nil {
			t.Fatal("error = nil, want start failure after rollback")
		}
	})

	t.Run("start fails restore rename fails", func(t *testing.T) {
		u, svc := swapUpdater(t, "/target")
		svc.EXPECT().Stop().Return(nil)
		svc.EXPECT().Start().Return(errors.New("boom"))
		stubRename(t, func(src, dst string) error {
			if src == "/target.bak" {
				return errors.New("boom")
			}
			return nil
		})
		if err := u.swapBinary("/downloaded"); !errors.Is(err, ErrReplaceBinary) {
			t.Fatalf("error = %v, want ErrReplaceBinary", err)
		}
	})

	t.Run("start fails restart fails", func(t *testing.T) {
		u, svc := swapUpdater(t, "/target")
		svc.EXPECT().Stop().Return(nil)
		gomock.InOrder(
			svc.EXPECT().Start().Return(errors.New("first")),
			svc.EXPECT().Start().Return(errors.New("second")),
		)
		stubRename(t, func(src, dst string) error { return nil })
		if err := u.swapBinary("/downloaded"); err == nil {
			t.Fatal("error = nil, want failure")
		}
	})
}

func TestUpdate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		withReleaseURL(t, serve(t, 200, "fresh-binary").URL+"/%s/%s")
		withVersionURL(t, serve(t, 200, "1.2.3").URL)

		target := filepath.Join(t.TempDir(), "open-defender")
		os.WriteFile(target, []byte("old"), 0755)

		ctrl := gomock.NewController(t)
		svc := mocks.NewMockInstaller(ctrl)
		svc.EXPECT().BinaryPath().Return(target).AnyTimes()
		svc.EXPECT().ServiceName().Return("open-defender").AnyTimes()
		svc.EXPECT().Stop().Return(nil)
		svc.EXPECT().Start().Return(nil)

		u := &updater{svc: svc, in: bufio.NewReader(strings.NewReader("1.2.3\namd64\n")), out: io.Discard, client: http.DefaultClient}
		if err := u.Update(); err != nil {
			t.Fatalf("Update() error: %v", err)
		}
		if data, _ := os.ReadFile(target); string(data) != "fresh-binary" {
			t.Errorf("target = %q", data)
		}
	})

	t.Run("resolve version error", func(t *testing.T) {
		withVersionURL(t, "http://127.0.0.1:0")
		u := &updater{in: bufio.NewReader(strings.NewReader("")), out: io.Discard}
		if err := u.Update(); err == nil {
			t.Fatal("error = nil, want resolveVersion failure")
		}
	})

	t.Run("resolve arch error", func(t *testing.T) {
		withVersionURL(t, serve(t, 200, "1.2.3").URL)
		u := &updater{in: bufio.NewReader(strings.NewReader("1.2.3\nsparc\n")), out: io.Discard}
		if err := u.Update(); !errors.Is(err, ErrUnknownArch) {
			t.Fatalf("error = %v, want ErrUnknownArch", err)
		}
	})

	t.Run("download error", func(t *testing.T) {
		withReleaseURL(t, serve(t, 404, "").URL+"/%s/%s")
		withVersionURL(t, serve(t, 200, "1.2.3").URL)

		ctrl := gomock.NewController(t)
		svc := mocks.NewMockInstaller(ctrl)
		svc.EXPECT().BinaryPath().Return(filepath.Join(t.TempDir(), "open-defender")).AnyTimes()

		u := &updater{svc: svc, in: bufio.NewReader(strings.NewReader("1.2.3\namd64\n")), out: io.Discard, client: http.DefaultClient}
		if err := u.Update(); !errors.Is(err, ErrReleaseNotFound) {
			t.Fatalf("error = %v, want ErrReleaseNotFound", err)
		}
	})

	t.Run("swap error", func(t *testing.T) {
		withReleaseURL(t, serve(t, 200, "fresh").URL+"/%s/%s")
		withVersionURL(t, serve(t, 200, "1.2.3").URL)

		ctrl := gomock.NewController(t)
		svc := mocks.NewMockInstaller(ctrl)
		svc.EXPECT().BinaryPath().Return(filepath.Join(t.TempDir(), "open-defender")).AnyTimes()
		svc.EXPECT().Stop().Return(errors.New("boom"))

		u := &updater{svc: svc, in: bufio.NewReader(strings.NewReader("1.2.3\namd64\n")), out: io.Discard, client: http.DefaultClient}
		if err := u.Update(); err == nil {
			t.Fatal("error = nil, want swap failure")
		}
	})
}
