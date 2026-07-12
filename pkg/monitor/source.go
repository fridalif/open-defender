package monitor

import (
	"bufio"
	"context"
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

func connectToDocker(ctx context.Context, cancel context.CancelFunc, containerName string, logsChan chan<- string) {
	defer close(logsChan)
	defer cancel()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("monitor.connectToDocker(containerName: %s) -> %v: %v", containerName, ErrCantConnectToDocker, err)
		return
	}
	defer cli.Close()

	reader, err := cli.ContainerLogs(ctx, containerName, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Tail:       "0",
	})
	if err != nil {
		log.Printf("monitor.connectToDocker(containerName: %s) -> %v: %v", containerName, ErrCantReadContainerLogs, err)
		return
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
			return
		case logsChan <- scanner.Text():
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("monitor.connectToDocker(containerName: %s) -> %v: %v", containerName, ErrCantReadContainerLogs, err)
	}
}

func connectToJournal(ctx context.Context, cancel context.CancelFunc, unitName string, logsChan chan<- string) {
	defer close(logsChan)
	defer cancel()

	j, err := sdjournal.NewJournal()
	if err != nil {
		log.Printf("monitor.connectToJournal(unitName: %s) -> %v: %v", unitName, ErrCantConnectToJournal, err)
		return
	}
	defer j.Close()

	if err := j.AddMatch("_SYSTEMD_UNIT=" + unitName); err != nil {
		log.Printf("monitor.connectToJournal(unitName: %s) -> %v: %v", unitName, ErrCantConnectToJournal, err)
		return
	}

	if err := j.SeekTail(); err != nil {
		log.Printf("monitor.connectToJournal(unitName: %s) -> %v: %v", unitName, ErrCantConnectToJournal, err)
		return
	}
	if _, err := j.Previous(); err != nil {
		log.Printf("monitor.connectToJournal(unitName: %s) -> %v: %v", unitName, ErrCantConnectToJournal, err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := j.Next()
		if err != nil {
			log.Printf("monitor.connectToJournal(unitName: %s) -> %v: %v", unitName, ErrCantReadJournal, err)
			return
		}

		if n == 0 {
			j.Wait(time.Second)
			continue
		}

		entry, err := j.GetEntry()
		if err != nil {
			log.Printf("monitor.connectToJournal(unitName: %s) -> %v: %v", unitName, ErrCantReadJournal, err)
			return
		}

		select {
		case logsChan <- entry.Fields["MESSAGE"]:
		case <-ctx.Done():
			return
		}
	}
}

func connectToSyslog(ctx context.Context, cancel context.CancelFunc, path string, logsChan chan<- string) {
	defer close(logsChan)
	defer cancel()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("monitor.connectToSyslog(path: %s) -> %v: %v", path, ErrCantWatchLogFile, err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(path); err != nil {
		log.Printf("monitor.connectToSyslog(path: %s) -> %v: %v", path, ErrCantWatchLogFile, err)
		return
	}

	file, err := os.Open(path)
	if err != nil {
		log.Printf("monitor.connectToSyslog(path: %s) -> %v: %v", path, ErrCantOpenLogFile, err)
		return
	}
	defer file.Close()

	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		log.Printf("monitor.connectToSyslog(path: %s) -> %v: %v", path, ErrCantReadLogFile, err)
		return
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
			return

		case event, ok := <-watcher.Events:
			if !ok {
				log.Printf("monitor.connectToSyslog(path: %s) -> %v", path, ErrWatcherClosed)
				return
			}
			if event.Has(fsnotify.Write) {
				readNewLines()
			}
			if event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove) {
				file.Close()
				newFile, err := os.Open(path)
				if err != nil {
					log.Printf("monitor.connectToSyslog(path: %s) -> %v: %v", path, ErrCantOpenLogFile, err)
					return
				}
				file = newFile
				reader = bufio.NewReader(file)
				if err := watcher.Add(path); err != nil {
					log.Printf("monitor.connectToSyslog(path: %s) -> %v: %v", path, ErrCantWatchLogFile, err)
					return
				}
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				log.Printf("monitor.connectToSyslog(path: %s) -> %v", path, ErrWatcherClosed)
				return
			}
			log.Printf("monitor.connectToSyslog(path: %s) -> %v: %v", path, ErrCantWatchLogFile, err)
			return
		}
	}
}
