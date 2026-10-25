package lsmactions

import (
	"fmt"
	"os"
	"strings"
)

type LSMActions interface {
	CheckIsActive() (bool, error)
	WriteLSMHelperMessage()
}

type lsmActions struct {
}

func NewLSMActions() LSMActions {
	return &lsmActions{}
}

func (la *lsmActions) CheckIsActive() (bool, error) {
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false, err
	}
	return strings.Contains(string(data), "bpf"), nil
}

func (la *lsmActions) WriteLSMHelperMessage() {
	fmt.Println("It is possible that BPF LSM is not enabled; check this, and if it is indeed disabled, enable it in GRUB and reboot the system.")
	fmt.Println("Modules which cant work without LSM:")
	fmt.Println("\t- User Command Controller")
	fmt.Println("For help write in Github Issues")
	fmt.Println("How check and add to GRUB (ensure neatness, always do grub backup):")
	fmt.Println("\t1) Check file /sys/kernel/security/lsm")
	fmt.Println("\t\t- if not exists possible disabled;")
	fmt.Println("\t\t- if exists and not contains bpf - disabled;")
	fmt.Println("\t2) Read /etc/default/grub file and /etc/default/grub.d folder")
	fmt.Println("\t\t- if substring lsm= not exists not in a single file append lsm=</sys/kernel/security/lsm content>,bpf in last file")
	fmt.Println("\t\t- if exists and not contains bpf module append this")
	fmt.Println("\t3) Execute command update-grub")
	fmt.Println("\t4) Restart system")

}
