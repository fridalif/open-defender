package monitor

import "time"

var (
	journalEmerge  = 0
	journalAlert   = 1
	journalCrit    = 2
	journalErr     = 3
	journalWarning = 4
	journalNotice  = 5
	journalInfo    = 6
	journalDebug   = 7
)

var (
	resourcePollInterval = 5 * time.Second
	windowPollInterval   = 1 * time.Second
)

var (
	sourceRetryInterval      = 15 * time.Second
	openLogFileRetries       = 10
	openLogFileRetryInterval = 500 * time.Millisecond
)
