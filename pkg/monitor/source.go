package monitor

import (
	"bufio"
	"context"
	"io"
	"os"
	"time"

	"github.com/coreos/go-systemd/v22/sdjournal"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/fsnotify/fsnotify"
)

func connectToDocker(ctx context.Context, containerName string, logsChan chan<- string) error {
	defer close(logsChan)

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer cli.Close()

	reader, err := cli.ContainerLogs(ctx, containerName, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Tail:       "0",
	})
	if err != nil {
		return err
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
			return ctx.Err()
		case logsChan <- scanner.Text():
		}
	}

	return scanner.Err()
}

func connectToJournal(ctx context.Context, unitName string, logsChan chan<- string) error {
	j, err := sdjournal.NewJournal()
	if err != nil {
		return err
	}
	defer j.Close()

	if err := j.AddMatch("_SYSTEMD_UNIT=" + unitName); err != nil {
		return err
	}

	if err := j.SeekTail(); err != nil {
		return err
	}
	if _, err := j.Previous(); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := j.Next()
		if err != nil {
			return err
		}

		if n == 0 {
			j.Wait(time.Second)
			continue
		}

		entry, err := j.GetEntry()
		if err != nil {
			return err
		}

		select {
		case logsChan <- entry.Fields["MESSAGE"]:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func connectToSyslog(ctx context.Context, path string, logsChan chan<- string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	if err := watcher.Add(path); err != nil {
		return err
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return err
	}

	reader := bufio.NewReader(file)

	readNewLines := func() error {
		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				select {
				case logsChan <- line:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			if err != nil {
				return nil
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if event.Has(fsnotify.Write) {
				if err := readNewLines(); err != nil {
					return err
				}
			}
			if event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove) {
				file.Close()
				newFile, err := os.Open(path)
				if err != nil {
					return err
				}
				file = newFile
				reader = bufio.NewReader(file)
				if err := watcher.Add(path); err != nil {
					return err
				}
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			return err
		}
	}
}
