//go:build windows

package secureio

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("secureio: create parent: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("secureio: write: %w", err)
	}
	if err := restrictToCurrentUser(path); err != nil {
		if os.Getenv("CHAINSAW_VERBOSE") != "" {
			fmt.Fprintf(os.Stderr, "chainsaw: secureio ACL hardening failed: %v\n", err)
		}
	}
	return nil
}

// restrictToCurrentUser replaces the file's DACL with a protected ACL granting
// full control to the current user's SID only, so the file cannot be read via
// inherited permissions from a permissive parent directory.
func restrictToCurrentUser(path string) error {
	token := windows.GetCurrentProcessToken()
	tu, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("set windows ACL: %w", err)
	}
	sidStr := tu.User.Sid.String()

	sddl := "D:P(A;;FA;;;" + sidStr + ")"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("set windows ACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("set windows ACL: %w", err)
	}

	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		return fmt.Errorf("set windows ACL: %w", err)
	}
	return nil
}
