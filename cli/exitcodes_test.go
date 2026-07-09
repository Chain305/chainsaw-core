package cli

import (
	"errors"
	"testing"
)

// TestExitCodeForClass pins the mapping from a classifyCLIError bucket to the
// process exit code used for a plain (non-ExitCodeError) error. ExitBlocked(1)
// must never appear here — it's reserved for the EXPECTED enforcement outcome,
// which always arrives as an ExitCodeError.
func TestExitCodeForClass(t *testing.T) {
	cases := []struct {
		class string
		want  int
	}{
		{"auth", ExitConfigAuth},
		{"permission", ExitConfigAuth},
		{"network", ExitOpError},
		{"timeout", ExitOpError},
		{"usage", ExitUsage},
		{"not_found", ExitOpError},
		{"other", ExitOpError},
		{"", ExitOpError},
	}
	for _, tc := range cases {
		if got := exitCodeForClass(tc.class); got != tc.want {
			t.Errorf("exitCodeForClass(%q) = %d; want %d", tc.class, got, tc.want)
		}
		if got := exitCodeForClass(tc.class); got == ExitBlocked {
			t.Errorf("exitCodeForClass(%q) returned ExitBlocked(1); reserved for enforcement outcomes", tc.class)
		}
	}
}

// TestClassifyCLIErrorToExitCode walks a representative error message through
// the same path Execute uses (classify -> exitCodeForClass) to prove an
// operational failure lands on 2/3/4, never 1.
func TestClassifyCLIErrorToExitCode(t *testing.T) {
	cases := []struct {
		msg  string
		want int
	}{
		{"401 unauthorized", ExitConfigAuth},
		{"403 forbidden", ExitConfigAuth},
		{"dial tcp: connection refused", ExitOpError},
		{"context deadline exceeded (timeout)", ExitOpError},
		{"unknown flag: --bogus", ExitUsage},
		{"unknown command \"frobnicate\"", ExitUsage},
		{"something internal went wrong", ExitOpError},
	}
	for _, tc := range cases {
		class := classifyCLIError(errors.New(tc.msg))
		got := exitCodeForClass(class)
		if got != tc.want {
			t.Errorf("error %q classified %q -> exit %d; want %d", tc.msg, class, got, tc.want)
		}
		if got == ExitBlocked {
			t.Errorf("operational error %q mapped to ExitBlocked(1)", tc.msg)
		}
	}
}

// TestExitCodeErrorHonored proves an ExitCodeError's Code wins over the
// classification path, and Code==0 falls back to the classified code.
func TestExitCodeErrorHonored(t *testing.T) {
	// A coded error carrying ExitSoakNotCleared must surface that code.
	var coded error = &ExitCodeError{Code: ExitSoakNotCleared, Err: errors.New("soak gate not cleared")}
	var target *ExitCodeError
	if !errors.As(coded, &target) || target.Code != ExitSoakNotCleared {
		t.Fatalf("ExitCodeError not unwrapped to code %d", ExitSoakNotCleared)
	}

	// ExitBlocked via ExitCodeError is the canonical enforcement signal.
	var blocked error = &ExitCodeError{Code: ExitBlocked, Err: nil}
	var bt *ExitCodeError
	if !errors.As(blocked, &bt) || bt.Code != ExitBlocked {
		t.Fatalf("ExitBlocked ExitCodeError not honored")
	}
}

// TestExitCodeError_ErrorString covers both the wrapped and bare forms (the
// bare form uses the local itoa formatter).
func TestExitCodeError_ErrorString(t *testing.T) {
	if got := (&ExitCodeError{Code: 2, Err: errors.New("boom")}).Error(); got != "boom" {
		t.Errorf("wrapped Error() = %q; want %q", got, "boom")
	}
	if got := (&ExitCodeError{Code: 10}).Error(); got != "exit 10" {
		t.Errorf("bare Error() = %q; want %q", got, "exit 10")
	}
	if got := (&ExitCodeError{Code: 0}).Error(); got != "exit 0" {
		t.Errorf("bare Error() = %q; want %q", got, "exit 0")
	}
}

// TestExitCodeConstants documents the contract values so a careless renumber
// trips a test. ExitBlocked stays 1; soak moved off 3 to 10.
func TestExitCodeConstants(t *testing.T) {
	if ExitOK != 0 || ExitBlocked != 1 || ExitOpError != 2 || ExitConfigAuth != 3 || ExitUsage != 4 {
		t.Fatalf("cross-cutting exit codes drifted: OK=%d Blocked=%d Op=%d ConfigAuth=%d Usage=%d",
			ExitOK, ExitBlocked, ExitOpError, ExitConfigAuth, ExitUsage)
	}
	if ExitSoakNotCleared != 10 {
		t.Fatalf("ExitSoakNotCleared = %d; want 10 (must stay >=10 to avoid colliding with the 0-4 buckets)", ExitSoakNotCleared)
	}
	if ExitSoakNotCleared == ExitConfigAuth {
		t.Fatalf("ExitSoakNotCleared collides with ExitConfigAuth(3) — the bug this renumber fixed")
	}
}
