package monitor

import (
	"bufio"
	"context"
	"io"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

func ConnectToDocker(ctx context.Context, containerName string, logsChan chan<- string) error {
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
			return nil
		case logsChan <- scanner.Text():
		}
	}

	return scanner.Err()
}
