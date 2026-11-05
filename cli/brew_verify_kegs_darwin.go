package cli

import (
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func macOSMajor() (int, error) {
	v, err := unix.Sysctl("kern.osproductversion")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.SplitN(v, ".", 2)[0])
}
