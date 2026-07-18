//go:build integration

package monitor

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
)

func drain(ch <-chan string) {
	go func() {
		for range ch {
		}
	}()
}

func waitFor(ch <-chan string, want string, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		select {
		case line := <-ch:
			if strings.Contains(line, want) {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

func TestAttachToSyslogRotationIntegration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan string, 100)
	done := make(chan struct{})
	go func() {
		connectToSyslog(ctx, path, ch)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)

	appendLine := func(text string) {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString(text)
		f.Close()
	}

	appendLine("before-rotation 1.1.1.1\n")
	if !waitFor(ch, "before-rotation", 3*time.Second) {
		t.Fatal("did not read the line before rotation")
	}

	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond)
	appendLine("after-rotation 2.2.2.2\n")
	if !waitFor(ch, "after-rotation", 3*time.Second) {
		t.Fatal("reading did not continue on the rotated file")
	}

	cancel()
	drain(ch)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("connectToSyslog did not stop after cancel")
	}
}

func TestConnectToJournalIntegration(t *testing.T) {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Skip("systemd is not running, skipping journal integration test")
	}

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan string, 100)
	done := make(chan struct{})
	go func() {
		connectToJournal(ctx, "systemd-journald.service", ch)
		close(done)
	}()
	drain(ch)

	time.Sleep(300 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("connectToJournal did not stop after cancel")
	}
}

func TestConnectToDockerIntegration(t *testing.T) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Skipf("no docker client: %v", err)
	}
	defer cli.Close()

	pingCtx, pingCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer pingCancel()
	if _, err := cli.Ping(pingCtx); err != nil {
		t.Skipf("docker daemon not reachable: %v", err)
	}

	const imageRef = "busybox:latest"
	bg := context.Background()

	if reader, err := cli.ImagePull(bg, "docker.io/library/"+imageRef, image.PullOptions{}); err == nil {
		io.Copy(io.Discard, reader)
		reader.Close()
	}

	name := fmt.Sprintf("opendefender-inttest-%d", os.Getpid())

	created, err := cli.ContainerCreate(bg, &container.Config{
		Image: imageRef,
		Cmd:   []string{"sh", "-c", "while true; do echo docker-integration-line; sleep 1; done"},
	}, nil, nil, nil, name)
	if err != nil {
		t.Skipf("cannot create container (image likely unavailable offline): %v", err)
	}
	defer cli.ContainerRemove(bg, created.ID, container.RemoveOptions{Force: true})

	if err := cli.ContainerStart(bg, created.ID, container.StartOptions{}); err != nil {
		t.Fatalf("ContainerStart: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan string, 100)
	done := make(chan struct{})
	go func() {
		connectToDocker(ctx, name, ch)
		close(done)
	}()

	got := waitFor(ch, "docker-integration-line", 15*time.Second)

	cancel()
	drain(ch)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("connectToDocker did not stop after cancel")
	}

	if !got {
		t.Fatal("did not receive the container log line")
	}
}
