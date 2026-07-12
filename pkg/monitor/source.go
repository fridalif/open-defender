package monitor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/coreos/go-systemd/v22/sdjournal"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/fsnotify/fsnotify"
)

func connectToDocker(ctx context.Context, containerName string, logsChan chan<- string) {
	runSource(ctx, fmt.Sprintf("connectToDocker(containerName: %s)", containerName), logsChan,
		func(ctx context.Context, logsChan chan<- string) error {
			return attachToDocker(ctx, containerName, logsChan)
		})
}

func connectToJournal(ctx context.Context, unitName string, logsChan chan<- string) {
	runSource(ctx, fmt.Sprintf("connectToJournal(unitName: %s)", unitName), logsChan,
		func(ctx context.Context, logsChan chan<- string) error {
			return attachToJournal(ctx, unitName, logsChan)
		})
}

func connectToSyslog(ctx context.Context, path string, logsChan chan<- string) {
	runSource(ctx, fmt.Sprintf("connectToSyslog(path: %s)", path), logsChan,
		func(ctx context.Context, logsChan chan<- string) error {
			return attachToSyslog(ctx, path, logsChan)
		})
}

func runSource(ctx context.Context, name string, logsChan chan<- string, attach func(context.Context, chan<- string) error) {
	defer close(logsChan)

	for {
		if err := attach(ctx, logsChan); err != nil && ctx.Err() == nil {
			log.Printf("monitor.%s -> %v, retrying in %s", name, err, sourceRetryInterval)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(sourceRetryInterval):
		}
	}
}

func attachToDocker(ctx context.Context, containerName string, logsChan chan<- string) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCantConnectToDocker, err)
	}
	defer cli.Close()

	reader, err := cli.ContainerLogs(ctx, containerName, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Tail:       "0",
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCantReadContainerLogs, err)
	}
	defer reader.Close()

	pr, pw := io.Pipe()
	go func() {
		_, err := stdcopy.StdCopy(pw, pw, reader)
		pw.CloseWithError(err)
	}()

	scanner := bufio.NewScanner(pr)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil
		case logsChan <- scanner.Text():
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrCantReadContainerLogs, err)
	}

	return fmt.Errorf("%w: logs of the container ended", ErrCantReadContainerLogs)
}

func attachToJournal(ctx context.Context, unitName string, logsChan chan<- string) error {
	j, err := sdjournal.NewJournal()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCantConnectToJournal, err)
	}
	defer j.Close()

	if err := j.AddMatch("_SYSTEMD_UNIT=" + unitName); err != nil {
		return fmt.Errorf("%w: %v", ErrCantConnectToJournal, err)
	}

	if err := j.SeekTail(); err != nil {
		return fmt.Errorf("%w: %v", ErrCantConnectToJournal, err)
	}
	if _, err := j.Previous(); err != nil {
		return fmt.Errorf("%w: %v", ErrCantConnectToJournal, err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		n, err := j.Next()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrCantReadJournal, err)
		}

		if n == 0 {
			j.Wait(time.Second)
			continue
		}

		entry, err := j.GetEntry()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrCantReadJournal, err)
		}

		select {
		case logsChan <- entry.Fields["MESSAGE"]:
		case <-ctx.Done():
			return nil
		}
	}
}

func attachToSyslog(ctx context.Context, path string, logsChan chan<- string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCantWatchLogFile, err)
	}
	defer watcher.Close()

	file, err := openLogFile(ctx, path)
	if err != nil {
		return err
	}
	defer func() {
		file.Close()
	}()

	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("%w: %v", ErrCantReadLogFile, err)
	}

	if err := watcher.Add(path); err != nil {
		return fmt.Errorf("%w: %v", ErrCantWatchLogFile, err)
	}

	reader := bufio.NewReader(file)

	readNewLines := func() {
		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				select {
				case logsChan <- line:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil

		case event, ok := <-watcher.Events:
			if !ok {
				return fmt.Errorf("%w", ErrWatcherClosed)
			}
			if event.Has(fsnotify.Write) {
				readNewLines()
			}
			if event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove) {
				readNewLines()
				file.Close()

				newFile, err := openLogFile(ctx, path)
				if err != nil {
					return err
				}

				file = newFile
				reader = bufio.NewReader(file)

				if err := watcher.Add(path); err != nil {
					return fmt.Errorf("%w: %v", ErrCantWatchLogFile, err)
				}
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return fmt.Errorf("%w", ErrWatcherClosed)
			}
			return fmt.Errorf("%w: %v", ErrCantWatchLogFile, err)
		}
	}
}

func openLogFile(ctx context.Context, path string) (*os.File, error) {
	var err error

	for range openLogFileRetries {
		var file *os.File

		file, err = os.Open(path)
		if err == nil {
			return file, nil
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %v", ErrCantOpenLogFile, err)
		case <-time.After(openLogFileRetryInterval):
		}
	}

	return nil, fmt.Errorf("%w: %v", ErrCantOpenLogFile, err)
}
