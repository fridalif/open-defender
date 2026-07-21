package ebpfmonitors

import "errors"

var (
	ErrCantLoadObjects   = errors.New("cant load ebpf objects")
	ErrCantAttachProgram = errors.New("cant attach ebpf program")
	ErrCantOpenRingbuf   = errors.New("cant open ringbuf reader")
)
