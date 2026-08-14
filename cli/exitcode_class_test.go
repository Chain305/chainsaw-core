package cli

import (
	"errors"
	"testing"
)

// TestClassifyCLIError_RequiredFlagIsUsage pins the cobra argument-shape error
// this CLI produces most often. Fourteen commands declare a required flag, so
// `required flag(s) "bundle", "input" not set` is the single most likely way a
// user gets the invocation wrong — and it used to fall through to "other",
// which exitCodeForClass maps to ExitOpError(2). CI reading that code saw
// "infrastructure failure" for an incomplete command line, while the sibling
// mistake (`--nonexistent-flag`) on the SAME command correctly exited 4.
func TestClassifyCLIError_RequiredFlagIsUsage(t *testing.T) {
	for _, msg := range []string{
		`required flag(s) "bundle", "input" not set`,
		`required flag(s) "name" not set`,
		`required flag(s) "bom", "bundle" not set`,
	} {
		if got := classifyCLIError(errors.New(msg)); got != "usage" {
			t.Errorf("classifyCLIError(%q) = %q, want %q", msg, got, "usage")
		}
		if got := exitCodeForClass(classifyCLIError(errors.New(msg))); got != ExitUsage {
			t.Errorf("exit code for %q = %d, want ExitUsage(%d)", msg, got, ExitUsage)
		}
	}
}

// TestClassifyCLIError_NotSetAloneIsNotUsage guards the conjunction in the
// switch arm above. "not set" is a common substring — a server error saying a
// config value is not set must NOT be reclassified as a usage error just
// because it shares two words with cobra's message.
func TestClassifyCLIError_NotSetAloneIsNotUsage(t *testing.T) {
	for _, msg := range []string{
		"CHAINSAW_JWT_SECRET is not set on this instance",
		"the reserved-namespace policy is not set",
	} {
		if got := classifyCLIError(errors.New(msg)); got == "usage" {
			t.Errorf("classifyCLIError(%q) = usage; a bare \"not set\" must not be a usage error", msg)
		}
	}
}

// TestClassForExitCode covers the fallback that keeps telemetry's error_class
// consistent with the process exit code. A command that states its outcome
// structurally — `return &ExitCodeError{Code: ExitUsage}` — carries no words
// for classifyCLIError to match, so it landed in "other" while exiting 4: the
// same failure reported two different ways.
func TestClassForExitCode(t *testing.T) {
	cases := map[int]string{
		ExitConfigAuth: "auth",
		ExitUsage:      "usage",
		ExitOpError:    "other",
		ExitOK:         "",
		ExitBlocked:    "",
		// Command-specific codes carry their own meaning; inventing a generic
		// class for them would be less informative than saying nothing.
		ExitSoakNotCleared: "",
		30:                 "",
	}
	for code, want := range cases {
		if got := classForExitCode(code); got != want {
			t.Errorf("classForExitCode(%d) = %q, want %q", code, got, want)
		}
	}
}

// TestClassForExitCodeIsConsistentWithExitCodeForClass pins the two directions
// against each other for the buckets classForExitCode claims to cover, so a
// future edit to either table cannot silently desync them.
func TestClassForExitCodeIsConsistentWithExitCodeForClass(t *testing.T) {
	for _, code := range []int{ExitConfigAuth, ExitUsage, ExitOpError} {
		class := classForExitCode(code)
		if class == "" {
			t.Fatalf("classForExitCode(%d) returned empty for a covered bucket", code)
		}
		if got := exitCodeForClass(class); got != code {
			t.Errorf("round-trip broken: classForExitCode(%d)=%q but exitCodeForClass(%q)=%d",
				code, class, class, got)
		}
	}
}
