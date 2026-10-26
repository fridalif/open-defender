package usercommandcontrollerpolicy

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

func Selected(hasUsers, hasCommands, userMatch, commandMatch bool) bool {
	return (hasUsers || hasCommands) && (!hasUsers || userMatch) && (!hasCommands || commandMatch)
}

func WouldBlock(blockType string, selected bool) bool {
	if blockType == "positive" {
		return selected
	}
	return !selected
}

func ParseUIDs(values []string) ([]uint32, error) {
	out := make([]uint32, 0, len(values))
	seen := make(map[uint32]struct{})
	for _, s := range values {
		if s == "" || strings.TrimSpace(s) != s {
			return nil, fmt.Errorf("invalid UID %q", s)
		}
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || n == 4294967295 { // (uid_t)-1 sentinel
			return nil, fmt.Errorf("invalid UID %q", s)
		}
		uid := uint32(n)
		if _, ok := seen[uid]; !ok {
			seen[uid] = struct{}{}
			out = append(out, uid)
		}
	}
	return out, nil
}

func NormalizeCommands(values []string) ([]string, error) {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{})
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value || strings.ContainsRune(value, '\x00') {
			return nil, fmt.Errorf("invalid command %q", value)
		}
		name := filepath.Base(value)
		if name == "." || name == "/" || len(name) > 63 {
			return nil, fmt.Errorf("invalid/too long command %q (max basename: 63 bytes)", value)
		}
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}
	return out, nil
}

func HostUID(uid uint32, uidMapText string) (uint32, bool, error) {
	lines := strings.Split(uidMapText, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 3 {
			return 0, false, fmt.Errorf("malformed uid_map line %q", line)
		}
		inside, e1 := strconv.ParseUint(fields[0], 10, 32)
		outside, e2 := strconv.ParseUint(fields[1], 10, 32)
		count, e3 := strconv.ParseUint(fields[2], 10, 32)
		if e1 != nil || e2 != nil || e3 != nil || count == 0 {
			return 0, false, fmt.Errorf("malformed uid_map line %q", line)
		}
		n := uint64(uid)
		if n >= inside && n-inside < count {
			mapped := outside + (n - inside)
			if mapped > 4294967295 {
				return 0, false, fmt.Errorf("UID overflow for %d", uid)
			}
			return uint32(mapped), true, nil
		}
	}
	return 0, false, nil
}
