package updater

//go:generate mockgen -source=updater.go -destination=mocks/updater_mock.go -package=mocks

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"open-defender/pkg/installer"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"
)

var (
	versionURL = "https://raw.githubusercontent.com/fridalif/open-defender/main/version.txt"
	releaseURL = "https://github.com/fridalif/open-defender/releases/download/%s/open-defender_%s"
)

const (
	fetchTimeout    = 15 * time.Second
	downloadTimeout = 10 * time.Minute
)

var releasedArches = []string{"amd64", "386", "arm64", "arm32"}

var versionPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

var (
	renameFile = os.Rename
	createTemp = os.CreateTemp
	copyFile   = io.Copy
	chmodFile  = os.Chmod
	readAll    = io.ReadAll
	goArch     = runtime.GOARCH
)

type Updater interface {
	Update() error
}

type updater struct {
	svc    installer.Installer
	in     *bufio.Reader
	out    io.Writer
	client *http.Client
}

func New(svc installer.Installer) Updater {
	return &updater{
		svc:    svc,
		in:     bufio.NewReader(os.Stdin),
		out:    os.Stdout,
		client: &http.Client{Timeout: downloadTimeout},
	}
}

func (u *updater) Update() error {
	version, err := u.resolveVersion()
	if err != nil {
		return fmt.Errorf("updater.Update() -> %w", err)
	}

	arch, err := u.resolveArch()
	if err != nil {
		return fmt.Errorf("updater.Update() -> %w", err)
	}

	url := fmt.Sprintf(releaseURL, version, arch)
	log.Printf("downloading %s", url)

	downloaded, err := u.download(url)
	if err != nil {
		return fmt.Errorf("updater.Update() -> %w", err)
	}
	defer os.Remove(downloaded)

	if err := u.swapBinary(downloaded); err != nil {
		return fmt.Errorf("updater.Update() -> %w", err)
	}

	log.Printf("%s updated to %s, check it with: systemctl status %s", u.svc.ServiceName(), version, u.svc.ServiceName())

	return nil
}

func (u *updater) swapBinary(downloaded string) error {
	target := u.svc.BinaryPath()
	backup := target + ".bak"

	if err := u.svc.Stop(); err != nil {
		return fmt.Errorf("updater.swapBinary() -> %w", err)
	}

	restore := false

	if err := renameFile(target, backup); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("updater.swapBinary() -> %w: %v", ErrReplaceBinary, err)
		}
	} else {
		restore = true
	}

	if err := renameFile(downloaded, target); err != nil {
		if restore {
			if restoreErr := renameFile(backup, target); restoreErr != nil {
				return fmt.Errorf("updater.swapBinary() -> %w: %v, the previous binary is left at %s", ErrReplaceBinary, err, backup)
			}

			if startErr := u.svc.Start(); startErr != nil {
				log.Println(startErr.Error())
			}
		}

		return fmt.Errorf("updater.swapBinary() -> %w: %v", ErrReplaceBinary, err)
	}

	if err := u.svc.Start(); err != nil {
		if !restore {
			return fmt.Errorf("updater.swapBinary() -> %w", err)
		}

		log.Printf("%v, rolling back to the previous binary", err)

		if restoreErr := renameFile(backup, target); restoreErr != nil {
			return fmt.Errorf("updater.swapBinary() -> %w: %v, the previous binary is left at %s", ErrReplaceBinary, restoreErr, backup)
		}

		if startErr := u.svc.Start(); startErr != nil {
			return fmt.Errorf("updater.swapBinary() -> %w", startErr)
		}

		return fmt.Errorf("updater.swapBinary() -> %w", err)
	}

	if restore {
		os.Remove(backup)
	}

	return nil
}

func (u *updater) download(url string) (string, error) {
	response, err := u.client.Get(url)
	if err != nil {
		return "", fmt.Errorf("updater.download() -> %w: %v", ErrDownloadRelease, err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("updater.download() -> %w: %s", ErrReleaseNotFound, url)
	}

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("updater.download() -> %w: %s: %s", ErrDownloadRelease, response.Status, url)
	}

	target := u.svc.BinaryPath()

	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return "", fmt.Errorf("updater.download() -> %w: %v", ErrWriteBinary, err)
	}

	file, err := createTemp(filepath.Dir(target), filepath.Base(target)+".new-*")
	if err != nil {
		return "", fmt.Errorf("updater.download() -> %w: %v", ErrWriteBinary, err)
	}
	defer file.Close()

	if _, err := copyFile(file, response.Body); err != nil {
		os.Remove(file.Name())
		return "", fmt.Errorf("updater.download() -> %w: %v", ErrWriteBinary, err)
	}

	if err := chmodFile(file.Name(), 0755); err != nil {
		os.Remove(file.Name())
		return "", fmt.Errorf("updater.download() -> %w: %v", ErrWriteBinary, err)
	}

	return file.Name(), nil
}

func (u *updater) resolveVersion() (string, error) {
	suggestion, err := u.fetchVersion()
	if err != nil {
		log.Printf("%v, enter the version by hand", err)
	}

	answer, err := u.ask("version", suggestion)
	if err != nil {
		return "", fmt.Errorf("updater.resolveVersion() -> %w", err)
	}

	if answer == "" {
		return "", fmt.Errorf("updater.resolveVersion() -> %w", ErrEmptyVersion)
	}

	if !versionPattern.MatchString(answer) {
		return "", fmt.Errorf("updater.resolveVersion() -> %w: %q", ErrInvalidVersion, answer)
	}

	return answer, nil
}

func (u *updater) fetchVersion() (string, error) {
	client := &http.Client{Timeout: fetchTimeout}

	response, err := client.Get(versionURL)
	if err != nil {
		return "", fmt.Errorf("updater.fetchVersion() -> %w: %v", ErrFetchVersion, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("updater.fetchVersion() -> %w: %s", ErrFetchVersion, response.Status)
	}

	body, err := readAll(io.LimitReader(response.Body, 256))
	if err != nil {
		return "", fmt.Errorf("updater.fetchVersion() -> %w: %v", ErrFetchVersion, err)
	}

	version := strings.TrimSpace(string(body))
	if version == "" {
		return "", fmt.Errorf("updater.fetchVersion() -> %w: %s is empty", ErrFetchVersion, versionURL)
	}

	if !versionPattern.MatchString(version) {
		return "", fmt.Errorf("updater.fetchVersion() -> %w: %q", ErrInvalidVersion, version)
	}

	return version, nil
}

func (u *updater) resolveArch() (string, error) {
	suggestion, err := u.detectArch()
	if err != nil {
		log.Printf("%v, enter the architecture by hand", err)
	}

	answer, err := u.ask(fmt.Sprintf("architecture (%s)", strings.Join(releasedArches, ", ")), suggestion)
	if err != nil {
		return "", fmt.Errorf("updater.resolveArch() -> %w", err)
	}

	if !slices.Contains(releasedArches, answer) {
		return "", fmt.Errorf("updater.resolveArch() -> %w: %q, expected one of: %s", ErrUnknownArch, answer, strings.Join(releasedArches, ", "))
	}

	return answer, nil
}

func (u *updater) detectArch() (string, error) {
	switch goArch {
	case "amd64":
		return "amd64", nil
	case "386":
		return "386", nil
	case "arm64":
		return "arm64", nil
	case "arm":
		return "arm32", nil
	default:
		return "", fmt.Errorf("updater.detectArch() -> %w: %s", ErrUnknownArch, goArch)
	}
}

func (u *updater) ask(prompt string, suggestion string) (string, error) {
	if suggestion != "" {
		fmt.Fprintf(u.out, "%s [%s]: ", prompt, suggestion)
	} else {
		fmt.Fprintf(u.out, "%s: ", prompt)
	}

	line, err := u.in.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		return "", fmt.Errorf("updater.ask() -> %w: %v", ErrReadInput, err)
	}

	answer := strings.TrimSpace(line)
	if answer == "" {
		return suggestion, nil
	}

	return answer, nil
}
