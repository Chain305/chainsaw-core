package githubactions

import (
	"os"
	"path/filepath"
	"testing"
)

// lintCases are workflow fixtures for LintWorkflow. Each names the signals
// it must raise; every case is also a negative for the signals it omits.
var lintCases = []struct {
	name string
	yaml string
	want []string
}{
	{
		// aquasecurity/trivy apidiff.yaml, 2026-02: pull_request_target
		// checked out the fork's head and ran it.
		name: "pull_request_target checks out the PR head then runs",
		yaml: `on: pull_request_target
jobs:
  apidiff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make apidiff
`,
		want: []string{SignalActionPwnRequest},
	},
	{
		name: "refs/pull merge ref under a mapping trigger",
		yaml: `on:
  pull_request_target:
    types: [opened]
jobs:
  t:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.number }}/merge
      - run: npm test
`,
		want: []string{SignalActionPwnRequest},
	},
	{
		name: "workflow_run checks out github.head_ref",
		yaml: `on: [workflow_run]
jobs:
  t:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
      - run: ./build.sh
`,
		want: []string{SignalActionPwnRequest},
	},
	{
		name: "pull_request_target that only labels, no checkout",
		yaml: `on: pull_request_target
permissions:
  pull-requests: write
jobs:
  label:
    steps:
      - uses: actions/labeler@v5
`,
	},
	{
		name: "pull_request_target checking out the base, then running",
		yaml: `on: pull_request_target
jobs:
  t:
    steps:
      - uses: actions/checkout@v4
      - run: make lint
`,
	},
	{
		name: "head checkout with no run step after it",
		yaml: `on: pull_request_target
jobs:
  t:
    steps:
      - run: echo before
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
	},
	{
		name: "head checkout followed only by a uses: step",
		yaml: `on: pull_request_target
jobs:
  t:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/upload-artifact@v4
`,
	},
	{
		name: "plain pull_request may check out the head",
		yaml: `on: pull_request
jobs:
  t:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make test
`,
	},
	{
		// @7nohe, 2026-08: any commenter could trigger `npm publish`.
		name: "issue_comment publishes with no author_association guard",
		yaml: `on: issue_comment
jobs:
  release:
    if: contains(github.event.comment.body, '/release')
    steps:
      - uses: actions/checkout@v4
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
`,
		want: []string{SignalActionCommentTriggerUnguarded},
	},
	{
		name: "review comment trigger with id-token write",
		yaml: `on: pull_request_review_comment
permissions:
  id-token: write
jobs:
  deploy:
    steps:
      - run: echo deploy
`,
		want: []string{SignalActionCommentTriggerUnguarded},
	},
	{
		name: "issue_comment guarded by author_association on the job",
		yaml: `on: issue_comment
jobs:
  release:
    if: github.event.comment.author_association == 'MEMBER'
    steps:
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
`,
	},
	{
		name: "issue_comment guarded on the publish step itself",
		yaml: `on: issue_comment
jobs:
  release:
    steps:
      - run: echo hi
      - if: github.event.comment.author_association == 'OWNER'
        run: twine upload dist/*
`,
	},
	{
		name: "issue_comment with no privilege",
		yaml: `on: issue_comment
jobs:
  ack:
    steps:
      - run: echo thanks
`,
	},
	{
		// elementary-data, 2026-04: comment.body interpolated into a shell.
		name: "comment body interpolated into run",
		yaml: `on: issue_comment
jobs:
  t:
    if: github.event.comment.author_association == 'MEMBER'
    steps:
      - run: |
          echo "${{ github.event.comment.body }}"
`,
		want: []string{SignalActionScriptInjection},
	},
	{
		name: "head_ref interpolated into run",
		yaml: `on: pull_request
jobs:
  t:
    steps:
      - run: git push origin ${{ github.head_ref }}
`,
		want: []string{SignalActionScriptInjection},
	},
	{
		name: "issue number is not attacker text",
		yaml: `on: issues
jobs:
  t:
    steps:
      - run: echo ${{ github.event.issue.number }}
      - run: echo "$TITLE"
        env:
          TITLE: ${{ github.event.issue.title }}
`,
	},
}

func TestLintWorkflow(t *testing.T) {
	for _, tc := range lintCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := LintWorkflow("wf.yml", []byte(tc.yaml))
			if err != nil {
				t.Fatalf("LintWorkflow: %v", err)
			}
			var signals []string
			for _, f := range got {
				signals = append(signals, f.Signal)
				if f.Severity != "high" {
					t.Errorf("%s severity = %q, want high", f.Signal, f.Severity)
				}
				if f.Ref.SourceFile != "wf.yml" || f.Ref.SourceLine == 0 {
					t.Errorf("%s has no location: %+v", f.Signal, f.Ref)
				}
				if f.Message == "" {
					t.Errorf("%s has no message", f.Signal)
				}
			}
			if len(signals) != len(tc.want) {
				t.Fatalf("signals = %v, want %v", signals, tc.want)
			}
			for i := range signals {
				if signals[i] != tc.want[i] {
					t.Fatalf("signals = %v, want %v", signals, tc.want)
				}
			}
		})
	}
}

func TestLintWorkflowFixtureFile(t *testing.T) {
	path := filepath.Join("testdata", "dangerous_triggers.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LintWorkflow(path, data)
	if err != nil {
		t.Fatalf("LintWorkflow: %v", err)
	}
	seen := map[string]int{}
	for _, f := range got {
		seen[f.Signal] = f.Ref.SourceLine
	}
	for sig, line := range map[string]int{
		SignalActionPwnRequest:              14,
		SignalActionScriptInjection:         16,
		SignalActionCommentTriggerUnguarded: 18,
	} {
		if seen[sig] != line {
			t.Errorf("%s at line %d, want %d (all: %+v)", sig, seen[sig], line, seen)
		}
	}
}

// TestLintFindingsReachTheRiskEngine: lint findings carry no `uses:` ref,
// so the projection must key them on file:line and still fire the signals.
func TestLintFindingsReachTheRiskEngine(t *testing.T) {
	path := filepath.Join("testdata", "dangerous_triggers.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := LintWorkflow(path, data)
	if err != nil {
		t.Fatal(err)
	}
	block := EvaluateRisk(findings)
	for _, want := range []string{SignalActionPwnRequest, SignalActionCommentTriggerUnguarded, SignalActionScriptInjection} {
		found := false
		for _, s := range block.Signals {
			found = found || s == want
		}
		if !found {
			t.Errorf("risk signals %v missing %s", block.Signals, want)
		}
	}
	if locs, _ := block.Fields["ActionPwnRequestLocs"].([]string); len(locs) != 1 || locs[0] != path+":14" {
		t.Errorf("ActionPwnRequestLocs = %v, want [%s:14]", block.Fields["ActionPwnRequestLocs"], path)
	}
}

func TestLintWorkflowMalformed(t *testing.T) {
	if _, err := LintWorkflow("bad.yml", []byte("on: [\n")); err == nil {
		t.Fatal("expected a parse error")
	}
}

// TestDecodeExec: a decoded payload handed to an interpreter is flagged; a
// decode written to a file or parsed as data, and a curl | sh installer, are
// not (Megalodon, 2026-05: `echo <base64> | base64 -d | bash`).
func TestDecodeExec(t *testing.T) {
	for _, run := range []string{
		`echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash`,
		`echo $P | base64 --decode | sudo -E sh`,
		"printf %s \"$P\" \\\n  | base64 -d \\\n  | bash -s -- x",
		`base64 -D <<< "$P" | /bin/bash`,
		`eval "$(echo $P | base64 -d)"`,
		`bash <(echo $P | base64 -d)`,
		`python3 -c "$(echo $P | base64 --decode)"`,
		`echo $P | base64 -di | python3`,
		`iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:P)))`,
		`powershell -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA`,
	} {
		if decodeExec(run) == "" {
			t.Errorf("not flagged: %q", run)
		}
	}
	for _, run := range []string{
		`echo "$KEYSTORE" | base64 -d > release.jks`,
		`echo "$GPG_KEY" | base64 --decode | gpg --batch --import`,
		`echo "$KUBECONFIG_B64" | base64 -d > ~/.kube/config && kubectl get pods`,
		`echo "$JSON" | base64 -d | python -m json.tool`,
		`echo "$X" | base64 -d | bash -c 'wc -c'`,
		`curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b /usr/local/bin`,
		`# echo $P | base64 -d | bash`,
		`base64 -w0 dist/app.zip | gh secret set APP`,
	} {
		if m := decodeExec(run); m != "" {
			t.Errorf("false positive on %q: %q", run, m)
		}
	}
}

func TestLintWorkflowDecodeExec(t *testing.T) {
	got, err := LintWorkflow("ci.yml", []byte(`on: workflow_dispatch
jobs:
  optimize:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: ci build optimization step
        run: echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Signal != SignalActionDecodeExec || got[0].Severity != "high" || got[0].Ref.SourceLine != 8 {
		t.Fatalf("want one high action.decode_exec at line 8, got %+v", got)
	}

	// A composite action's own steps are linted too.
	got, err = LintWorkflow("action.yml", []byte(`name: setup
runs:
  using: composite
  steps:
    - shell: bash
      run: echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash
`))
	if err != nil || len(got) != 1 || got[0].Signal != SignalActionDecodeExec || got[0].Ref.SourceLine != 6 {
		t.Fatalf("composite action: want one action.decode_exec at line 6, got %+v (%v)", got, err)
	}
}
