package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestDoctor_TextOutputListsAllManagers(t *testing.T) {
	withHookEnv(t)

	cmd := newDoctorCmd()
	// The root command provides --json; doctor inherits via rootCmd in
	// production. For tests we recreate it here.
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Bool("no-color", true, "")
	_ = cmd.Flags().Set("no-color", "true")

	cmd.SetArgs(nil)
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr: %s", err, errb.String())
	}

	text := out.String()
	if !strings.Contains(text, "MANAGER") {
		t.Fatalf("output missing MANAGER header: %q", text)
	}
	for _, name := range []string{"npm", "pip", "cargo"} {
		if !strings.Contains(text, name) {
			t.Fatalf("output missing %q row: %q", name, text)
		}
	}
	// The table should have at least header + one row per manager
	// registered in hook.All(). Use the smallest number the test can
	// trust to stay correct as managers are added.
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) < 4 {
		t.Fatalf("expected header + manager rows, got %d: %v", len(lines), lines)
	}
}

func TestDoctor_JSONOutput(t *testing.T) {
	withHookEnv(t)

	cmd := newDoctorCmd()
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Bool("no-color", true, "")
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set --json: %v", err)
	}

	cmd.SetArgs(nil)
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr: %s", err, errb.String())
	}

	var report doctorReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, out.String())
	}
	if len(report.Managers) < 3 {
		t.Fatalf("expected >= 3 managers in JSON, got %d: %+v", len(report.Managers), report.Managers)
	}
	want := map[string]bool{"npm": false, "pip": false, "cargo": false}
	for _, m := range report.Managers {
		if _, ok := want[m.Name]; ok {
			want[m.Name] = true
		}
		if m.ConfigPath == "" {
			t.Errorf("manager %q missing config_path", m.Name)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("JSON missing manager %q: %+v", name, report.Managers)
		}
	}
}
