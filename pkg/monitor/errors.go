package monitor

import "errors"

var (
	ErrCantConnectToDocker   = errors.New("cant connect to docker")
	ErrCantReadContainerLogs = errors.New("cant read container logs")
	ErrCantConnectToJournal  = errors.New("cant connect to journal")
	ErrCantReadJournal       = errors.New("cant read journal")
	ErrCantWatchLogFile      = errors.New("cant watch log file")
	ErrCantOpenLogFile       = errors.New("cant open log file")
	ErrCantReadLogFile       = errors.New("cant read log file")
	ErrWatcherClosed         = errors.New("log file watcher was closed")
	ErrEngineNotFound        = errors.New("engine not found or not exists")
	ErrCantGetCPUUsage       = errors.New("cant get cpu usage")
	ErrCantGetRAMUsage       = errors.New("cant get ram usage")
	ErrCantGetTrafficUsage   = errors.New("cant get traffic usage")
	ErrCantGetDiskUsage      = errors.New("cant get disk usage")
	ErrCantGetProcesses      = errors.New("cant get processes")
	ErrCantCreateSnapshotDir = errors.New("cant create snapshot directory")
	ErrCantWriteSnapshot     = errors.New("cant write snapshot")
	ErrCompileRegexp         = errors.New("cant compile regexp")
)
