package usercommandcontrollerpolicy

import (
	"strings"
	"testing"
)

func TestCommandPolicySelection(t *testing.T) {
	for _, tc := range []struct {
		name                                               string
		users, commands, userMatch, commandMatch, selected bool
	}{
		{"empty selectors", false, false, false, false, false},
		{"UID selected", true, false, true, false, true},
		{"UID excluded", true, false, false, true, false},
		{"command selected", false, true, false, true, true},
		{"command excluded", false, true, true, false, false},
		{"both matched", true, true, true, true, true},
		{"only UID matched", true, true, true, false, false},
		{"only command matched", true, true, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected := Selected(tc.users, tc.commands, tc.userMatch, tc.commandMatch)
			if selected != tc.selected {
				t.Fatalf("selected=%v want %v", selected, tc.selected)
			}
			if WouldBlock("positive", selected) != tc.selected || WouldBlock("negative", selected) == tc.selected {
				t.Fatal("incorrect positive/negative verdict")
			}
		})
	}
}
func TestRootUIDMapping(t *testing.T) {
	for _, tc := range []struct {
		name, mapping string
		host          uint32
		found         bool
	}{
		{"host", "0 0 4294967295\n", 0, true},
		{"remapped container", "0 100000 65536\n", 100000, true},
		{"nested mapping viewed from host", "0 200000 1\n1 300000 65535\n", 200000, true},
		{"root unmapped", "1000 100000 1000\n", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, found, err := HostUID(0, tc.mapping)
			if err != nil || found != tc.found || host != tc.host {
				t.Fatalf("host=%d found=%v err=%v", host, found, err)
			}
		})
	}
}
func TestCommandBasenameNormalization(t *testing.T) {
	got, err := NormalizeCommands([]string{"/usr/bin/curl", "curl", "wget"})
	if err != nil || len(got) != 2 || got[0] != "curl" || got[1] != "wget" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := NormalizeCommands([]string{strings.Repeat("x", 64)}); err == nil {
		t.Fatal("accepted truncated basename")
	}
}
