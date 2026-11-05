//go:build !darwin

package cli

import "errors"

func macOSMajor() (int, error) { return 0, errors.New("not macOS") }
