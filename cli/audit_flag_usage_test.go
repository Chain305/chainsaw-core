package cli

// audit_flag_usage_test.go covers Y7 for the three flags owned by audit.go,
// audit_export.go and exception.go.
//
// pflag's UnquoteUsage treats the FIRST back-quoted span in a usage string as
// the flag's VALUE PLACEHOLDER: it strips the backticks and prints that span in
// place of the type name. Prose backticks — the markdown habit of quoting a
// command name — therefore corrupt the help line: `audit export` in --limit's
// usage rendered as "--limit audit export" instead of "--limit int". It also
// strips only that first pair, so any SECOND pair leaks literal backticks into
// the help body.

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func TestFlagUsage_ProseBackticksDoNotHijackPlaceholders(t *testing.T) {
	cases := []struct {
		cmd             *cobra.Command
		flag            string
		wantPlaceholder string
	}{
		{auditViewCmd, "limit", "int"},              // "…`audit export` defaults to 0/all."
		{auditExportCmd, "limit", "int"},            // "…unlike `audit view` which defaults to 50"
		{exceptionCreateCmd, "cve", "string"},       // "Required for `chainsaw sbom vex export`…"
		{policySimulateCmd, "repository", "string"}, // "…report `conditional` rather than…"
	}
	for _, tc := range cases {
		t.Run(tc.cmd.Name()+"/--"+tc.flag, func(t *testing.T) {
			f := tc.cmd.Flags().Lookup(tc.flag)
			if f == nil {
				t.Fatalf("flag --%s not registered on %q", tc.flag, tc.cmd.Name())
			}
			placeholder, usage := pflag.UnquoteUsage(f)
			if placeholder != tc.wantPlaceholder {
				t.Errorf("--%s renders as \"--%s %s\"; prose backticks in the usage string hijacked the value placeholder (want %q)",
					tc.flag, tc.flag, placeholder, tc.wantPlaceholder)
			}
			// The trap: UnquoteUsage removes only the first pair, so a second
			// one would surface as literal backticks in the rendered help.
			if strings.Contains(usage, "`") {
				t.Errorf("--%s usage still carries a backtick after UnquoteUsage: %q", tc.flag, usage)
			}
		})
	}
}
