package githubactions

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseUsesString(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    ActionRef
		wantSHA bool
	}{
		{
			name: "simple step uses",
			raw:  "actions/checkout@v4",
			want: ActionRef{Raw: "actions/checkout@v4", Owner: "actions", Name: "checkout", Version: "v4", Kind: KindRemote},
		},
		{
			name:    "sha pin",
			raw:     "actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab",
			want:    ActionRef{Raw: "actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab", Owner: "actions", Name: "checkout", Version: "8e5e7e5ab8b370d6c329ec480221332ada57f0ab", SHA: "8e5e7e5ab8b370d6c329ec480221332ada57f0ab", Kind: KindRemote},
			wantSHA: true,
		},
		{
			name: "unpinned",
			raw:  "actions/checkout",
			want: ActionRef{Raw: "actions/checkout", Owner: "actions", Name: "checkout", Kind: KindRemote},
		},
		{
			name: "branch ref",
			raw:  "actions/checkout@main",
			want: ActionRef{Raw: "actions/checkout@main", Owner: "actions", Name: "checkout", Version: "main", Kind: KindRemote},
		},
		{
			name: "local action",
			raw:  "./.github/actions/my-action",
			want: ActionRef{Raw: "./.github/actions/my-action", Name: "./.github/actions/my-action", Kind: KindLocal},
		},
		{
			name: "docker action",
			raw:  "docker://alpine:3.18",
			want: ActionRef{Raw: "docker://alpine:3.18", Name: "alpine", Version: "3.18", Kind: KindDocker},
		},
		{
			name: "composite path subaction",
			raw:  "aws-actions/configure-aws-credentials/v1@v2",
			want: ActionRef{Raw: "aws-actions/configure-aws-credentials/v1@v2", Owner: "aws-actions", Name: "configure-aws-credentials/v1", Version: "v2", Kind: KindRemote},
		},
		{
			name: "malformed missing owner",
			raw:  "checkout@v4",
			want: ActionRef{Raw: "checkout@v4", Owner: "checkout", Version: "v4", Kind: KindUnknown},
		},
		{
			name: "empty",
			raw:  "",
			want: ActionRef{Raw: "", Kind: KindUnknown},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseUsesString(tc.raw)
			if got != tc.want {
				t.Fatalf("ParseUsesString(%q)\n got: %+v\nwant: %+v", tc.raw, got, tc.want)
			}
			if tc.wantSHA && got.SHA == "" {
				t.Fatalf("expected SHA populated for %q", tc.raw)
			}
			if !tc.wantSHA && got.SHA != "" {
				t.Fatalf("unexpected SHA populated for %q: %q", tc.raw, got.SHA)
			}
		})
	}
}

func TestParseWorkflowFile_Simple(t *testing.T) {
	data := mustRead(t, "testdata/simple.yml")
	refs, err := ParseWorkflowFile("testdata/simple.yml", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("want 2 refs, got %d (%+v)", len(refs), refs)
	}
	if refs[0].Owner != "actions" || refs[0].Name != "checkout" || refs[0].Version != "v4" {
		t.Fatalf("first ref unexpected: %+v", refs[0])
	}
	if refs[1].Owner != "actions" || refs[1].Name != "setup-node" || refs[1].Version != "v3" {
		t.Fatalf("second ref unexpected: %+v", refs[1])
	}
	// Both should have a 1-indexed line number > 0.
	for _, r := range refs {
		if r.SourceLine <= 0 {
			t.Fatalf("expected SourceLine > 0, got %+v", r)
		}
		if r.SourceFile != "testdata/simple.yml" {
			t.Fatalf("expected SourceFile, got %q", r.SourceFile)
		}
	}
}

func TestParseWorkflowFile_SHA(t *testing.T) {
	data := mustRead(t, "testdata/with_sha.yml")
	refs, err := ParseWorkflowFile("testdata/with_sha.yml", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 3 {
		t.Fatalf("want 3 refs, got %d", len(refs))
	}
	// First: SHA pin
	if refs[0].SHA == "" || refs[0].Version != refs[0].SHA {
		t.Fatalf("expected SHA-pinned first ref, got %+v", refs[0])
	}
	// Second: unpinned
	if refs[1].Version != "" || refs[1].SHA != "" {
		t.Fatalf("expected unpinned second ref, got %+v", refs[1])
	}
	// Third: branch ref, no SHA
	if refs[2].Version != "main" || refs[2].SHA != "" {
		t.Fatalf("expected branch-pinned third ref, got %+v", refs[2])
	}
}

func TestParseWorkflowFile_Local(t *testing.T) {
	data := mustRead(t, "testdata/with_local.yml")
	refs, err := ParseWorkflowFile("testdata/with_local.yml", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 1 || refs[0].Kind != KindLocal {
		t.Fatalf("want 1 local ref, got %+v", refs)
	}
	if refs[0].Owner != "" {
		t.Fatalf("local ref should have empty Owner, got %q", refs[0].Owner)
	}
}

func TestParseWorkflowFile_Docker(t *testing.T) {
	data := mustRead(t, "testdata/with_docker.yml")
	refs, err := ParseWorkflowFile("testdata/with_docker.yml", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 1 || refs[0].Kind != KindDocker {
		t.Fatalf("want 1 docker ref, got %+v", refs)
	}
	if refs[0].Name != "alpine" || refs[0].Version != "3.18" {
		t.Fatalf("unexpected docker ref: %+v", refs[0])
	}
}

func TestParseWorkflowFile_Multi(t *testing.T) {
	data := mustRead(t, "testdata/multi_step.yml")
	refs, err := ParseWorkflowFile("testdata/multi_step.yml", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 5 {
		t.Fatalf("want 5 refs (1 reusable + 3 matrix steps + 1 build step), got %d: %+v", len(refs), refs)
	}

	// Reusable workflow uses (job-level) should be present.
	var sawReusable bool
	for _, r := range refs {
		if r.Owner == "my-org" && r.Version == "v2" {
			sawReusable = true
		}
	}
	if !sawReusable {
		t.Fatalf("did not find job-level reusable workflow uses: %+v", refs)
	}

	// SourceLines should be strictly increasing as we walk the file.
	prev := 0
	for _, r := range refs {
		if r.SourceLine < prev {
			t.Fatalf("SourceLine not monotonically increasing: %+v", refs)
		}
		prev = r.SourceLine
	}
}

func TestParseWorkflowFile_Malformed(t *testing.T) {
	data := mustRead(t, "testdata/malformed.yml")
	_, err := ParseWorkflowFile("testdata/malformed.yml", data)
	if err == nil {
		t.Fatalf("expected error for malformed yaml, got nil")
	}
}

func TestParseWorkflowFile_NoJobs(t *testing.T) {
	data := []byte("name: no-jobs\non: [push]\n")
	refs, err := ParseWorkflowFile("inline.yml", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("expected empty refs, got %+v", refs)
	}
}

func TestParseWorkflowFile_EmptySteps(t *testing.T) {
	data := []byte("name: empty\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n")
	refs, err := ParseWorkflowFile("inline.yml", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("expected empty refs, got %+v", refs)
	}
}

func TestParseWorkflowDir(t *testing.T) {
	// Build a temp tree mirroring .github/workflows/ with a couple of files
	// and one non-yaml sibling that should be ignored.
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "a.yml"), mustRead(t, "testdata/simple.yml"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "b.yaml"), mustRead(t, "testdata/with_docker.yml"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "README.md"), []byte("ignore me"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Pass repo root.
	refs, err := ParseWorkflowDir(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 3 {
		t.Fatalf("want 3 refs from dir, got %d (%+v)", len(refs), refs)
	}

	// Pass workflows dir directly — should also work.
	refs2, err := ParseWorkflowDir(wfDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs2) != 3 {
		t.Fatalf("want 3 refs from workflows dir, got %d", len(refs2))
	}
}

func TestParseWorkflowDir_Missing(t *testing.T) {
	tmp := t.TempDir()
	refs, err := ParseWorkflowDir(filepath.Join(tmp, "does-not-exist"))
	if err != nil {
		t.Fatalf("expected nil error for missing dir, got %v", err)
	}
	if refs != nil {
		t.Fatalf("expected nil refs for missing dir, got %+v", refs)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
