package banpool

import "time"

type Ban struct {
	ID          int64
	IP          string
	BannedAt    time.Time
	BannedUntil time.Time
}
