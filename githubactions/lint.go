package githubactions

// lint.go — dangerous-trigger lint over a workflow's own structure.
//
// Scan judges the actions a workflow USES; this judges what the workflow
// DOES with its triggers and steps. Four shapes, each from a real compromise:
//
//   - action.pwn_request: pull_request_target / workflow_run checks out the
//     pull request's head and then runs a step. The fork's code runs with
//     the base repository's secrets and write token (aquasecurity/trivy
//     apidiff.yaml, 2026-02; kubernetes-el, 2026-03).
//   - action.comment_trigger_unguarded: an issue_comment /
//     pull_request_review_comment job holds secrets, `id-token: write` or a
//     publish step, and no `if:` checks the commenter's author_association —
//     any GitHub user can fire it (@7nohe `npm publish` comment, 2026-08).
//   - action.script_injection: attacker-written text (a comment body, an
//     issue or PR title, a branch name) is interpolated with ${{ }} straight
//     into a shell `run:` (elementary-data, 2026-04).
//   - action.decode_exec: a `run:` step decodes a payload (base64 -d,
//     FromBase64String) and executes it, so the script that runs cannot be
//     read in the workflow (Megalodon mass CI backdoor, 2026-05:
//     `echo <base64> | base64 -d | bash`). A plain `curl … | sh` installer is
//     deliberately NOT matched: it is ordinary in CI and its source is a URL
//     a reviewer can read.
//
// Like the parser, this is pure: no I/O, no network.

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Signal IDs for LintWorkflow findings. Registered in core/risk at weight 0.
const (
	SignalActionPwnRequest              = "action.pwn_request"
	SignalActionCommentTriggerUnguarded = "action.comment_trigger_unguarded"
	SignalActionScriptInjection         = "action.script_injection"
	SignalActionDecodeExec              = "action.decode_exec"
)

var (
	// untrustedHeadRe matches a checkout ref/repository that names the pull
	// request's head (or the triggering run's head) rather than the base.
	untrustedHeadRe = regexp.MustCompile(`github\.event\.pull_request\.head\.|refs/pull/|github\.head_ref|github\.event\.workflow_run\.head_`)

	// injectableExprRe matches a ${{ }} expression carrying attacker-written
	// text. github.event.issue.number and the like are not text and do not
	// match.
	injectableExprRe = regexp.MustCompile(`\$\{\{[^}]*\b(github\.event\.(comment\.body|issue\.title|issue\.body|pull_request\.title|pull_request\.body|pull_request\.head\.ref|review\.body|review_comment\.body)|github\.head_ref)\b[^}]*\}\}`)

	// publishRe matches a run: line that publishes an artifact.
	publishRe = regexp.MustCompile(`\b(npm|yarn|pnpm) publish\b|\btwine upload\b|\bcargo publish\b|\bgem push\b|\bpoetry publish\b|\bdocker push\b|\bgh release create\b|\bgoreleaser\b`)

	secretsRe = regexp.MustCompile(`\bsecrets\.`)

	// decodeRe matches a decode of an encoded payload.
	decodeRe = regexp.MustCompile(`(?i)\bbase64\s+(?:-[a-ce-z]*d[a-z]*|--decode)\b|\bFromBase64String\b`)

	// pipeExecRe matches a pipe into an interpreter that executes its stdin:
	// no argument, `-`, or `-s`. `| python -m json.tool` and `| bash -c '…'`
	// read stdin as data and do not match.
	pipeExecRe = regexp.MustCompile(`\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:/usr/bin/env\s+)?(?:/\S*/)?(?:sh|bash|zsh|dash|ksh|ash|python[0-9.]*|perl|node|ruby|php|pwsh)(?:\s+-s\b|\s+-(?:\s|$)|\s*(?:$|[;&|)]))`)

	// execWrapRe matches an executor whose argument is a substitution still
	// open at the decode: eval "$(… base64 -d)", bash <(… base64 -d),
	// python -c "$(… base64 -d)", iex / Invoke-Expression around a decode.
	execWrapRe = regexp.MustCompile("(?i)(?:\\beval\\s+|\\bsource\\s+|\\b(?:sh|bash|zsh|dash)\\s+(?:-c\\s+)?|\\b(?:python[0-9.]*|perl|node|ruby)\\s+-[ce]\\s+)[\"']?(?:\\$\\(|<\\(|`)[^)`]*$|\\b(?:iex|invoke-expression)\\b")

	// encodedCommandRe matches PowerShell's own decode-and-run flag with a
	// base64 argument.
	encodedCommandRe = regexp.MustCompile(`(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*\s-(?:e|ec|en|enc|encodedcommand)\s+["']?[A-Za-z0-9+/]{16,}={0,2}`)
)

// LintWorkflow parses one workflow and returns its dangerous-trigger
// findings, every one severity "high", located at a 1-indexed line of path.
// A YAML parse error is returned; a document that is not a workflow yields
// no findings.
func LintWorkflow(path string, data []byte) ([]Finding, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse workflow %s: %w", path, err)
	}
	doc := root.Content
	if len(doc) == 0 || deref(doc[0]).Kind != yaml.MappingNode {
		return nil, nil
	}
	wf := deref(doc[0])
	triggers := workflowTriggers(mapGet(wf, "on"))
	idTokenWorkflow := grantsIDToken(mapGet(wf, "permissions"))

	finding := func(signal string, line int, msg string) Finding {
		return Finding{
			Ref:      ActionRef{SourceFile: path, SourceLine: line},
			Signal:   signal,
			Severity: "high",
			Message:  msg,
		}
	}

	var out []Finding
	decodeExecs := func(where string, steps []*yaml.Node) {
		for _, s := range steps {
			if m := decodeExec(scalar(mapGet(s, "run"))); m != "" {
				out = append(out, finding(SignalActionDecodeExec, mapGetKey(s, "run").Line,
					fmt.Sprintf("%s: a run: step decodes a payload and executes it (%s); the code that runs cannot be read in the workflow", where, m)))
			}
		}
	}
	// A composite action's own steps (action.yml `runs.steps`): the
	// reviewdog/action-setup compromise (2025-03) hid its payload there.
	decodeExecs("composite action", stepsOf(mapGet(wf, "runs")))

	jobs := mapGet(wf, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return out, nil
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		jobName, job := jobs.Content[i], deref(jobs.Content[i+1])
		if job.Kind != yaml.MappingNode {
			continue
		}
		steps := stepsOf(job)

		// a) pwn request.
		if triggers["pull_request_target"] || triggers["workflow_run"] {
			if f, ok := pwnRequest(steps); ok {
				out = append(out, finding(SignalActionPwnRequest, f.line,
					fmt.Sprintf("job %q: a %s workflow checks out the pull request head (%s) and then runs it; the fork's code runs with this repository's secrets and write token", jobName.Value, triggerName(triggers), f.what)))
			}
		}

		// b) unguarded comment trigger.
		if (triggers["issue_comment"] || triggers["pull_request_review_comment"]) &&
			!strings.Contains(scalar(mapGet(job, "if")), "author_association") {
			if line, why := commentPrivilege(job, jobName, steps, idTokenWorkflow); line != 0 {
				out = append(out, finding(SignalActionCommentTriggerUnguarded, line,
					fmt.Sprintf("job %q: runs on any user's comment and %s, with no `if:` checking the commenter's author_association", jobName.Value, why)))
			}
		}

		// c) script injection.
		for _, s := range steps {
			run := mapGetKey(s, "run")
			if run == nil {
				continue
			}
			if m := injectableExprRe.FindString(scalar(mapGet(s, "run"))); m != "" {
				out = append(out, finding(SignalActionScriptInjection, run.Line,
					fmt.Sprintf("job %q: %s is interpolated into a shell run: step; attacker-written text becomes shell code (pass it through env: instead)", jobName.Value, m)))
			}
		}

		// d) decode and execute.
		decodeExecs(fmt.Sprintf("job %q", jobName.Value), steps)
	}
	return out, nil
}

// decodeExec returns the first line of a run: script that decodes a payload
// and executes it, or "". Backslash continuations are joined first so a
// pipeline split across lines is still one command.
func decodeExec(run string) string {
	for _, ln := range strings.Split(strings.ReplaceAll(run, "\\\n", " "), "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if encodedCommandRe.MatchString(t) {
			return truncate(t)
		}
		d := decodeRe.FindStringIndex(t)
		if d != nil && (pipeExecRe.MatchString(t[d[1]:]) || execWrapRe.MatchString(t[:d[0]])) {
			return truncate(t)
		}
	}
	return ""
}

// truncate keeps a finding message readable when the line carries a long
// encoded payload.
func truncate(s string) string {
	if len(s) > 120 {
		return s[:57] + "…" + s[len(s)-60:]
	}
	return s
}

type pwnHit struct {
	line int
	what string
}

// pwnRequest finds an actions/checkout of the untrusted head followed by a
// run: step in the same job.
func pwnRequest(steps []*yaml.Node) (pwnHit, bool) {
	var hit pwnHit
	for _, s := range steps {
		if hit.line != 0 && mapGetKey(s, "run") != nil {
			return hit, true
		}
		if hit.line != 0 {
			continue
		}
		ref := ParseUsesString(scalar(mapGet(s, "uses")))
		if !strings.EqualFold(ref.Owner, "actions") || !strings.EqualFold(stripSubPath(ref.Name), "checkout") {
			continue
		}
		with := mapGet(s, "with")
		for _, key := range []string{"ref", "repository"} {
			k := mapGetKey(with, key)
			if v := scalar(mapGet(with, key)); k != nil && untrustedHeadRe.MatchString(v) {
				hit = pwnHit{line: k.Line, what: key + ": " + v}
				break
			}
		}
	}
	return pwnHit{}, false
}

// commentPrivilege returns the line and a description of the first thing a
// comment-triggered job holds that a stranger must not get: a publish step
// or a secret on a step that is not itself author_association-guarded, or a
// job-level secret / id-token grant (which only the job's `if:` can guard).
func commentPrivilege(job, jobName *yaml.Node, steps []*yaml.Node, idTokenWorkflow bool) (int, string) {
	if grantsIDToken(mapGet(job, "permissions")) || (idTokenWorkflow && mapGet(job, "permissions") == nil) {
		return jobName.Line, "can mint an OIDC token (id-token: write)"
	}
	for _, key := range []string{"env", "secrets", "with"} {
		if v := mapGet(job, key); v != nil && (key == "secrets" || secretsRe.MatchString(nodeText(v))) {
			return jobName.Line, "passes repository secrets to the job"
		}
	}
	for _, s := range steps {
		if strings.Contains(scalar(mapGet(s, "if")), "author_association") {
			continue
		}
		if publishRe.MatchString(scalar(mapGet(s, "run"))) {
			return s.Line, "publishes (" + publishRe.FindString(scalar(mapGet(s, "run"))) + ")"
		}
		if secretsRe.MatchString(nodeText(s)) {
			return s.Line, "hands a repository secret to a step"
		}
	}
	return 0, ""
}

// workflowTriggers reads `on:` in any of its three forms: a scalar, a
// sequence of names, or a mapping keyed by name.
func workflowTriggers(on *yaml.Node) map[string]bool {
	out := map[string]bool{}
	if on == nil {
		return out
	}
	switch on.Kind {
	case yaml.ScalarNode:
		out[on.Value] = true
	case yaml.SequenceNode:
		for _, c := range on.Content {
			out[deref(c).Value] = true
		}
	case yaml.MappingNode:
		for i := 0; i < len(on.Content); i += 2 {
			out[on.Content[i].Value] = true
		}
	}
	return out
}

func triggerName(t map[string]bool) string {
	if t["pull_request_target"] {
		return "pull_request_target"
	}
	return "workflow_run"
}

// grantsIDToken reports `permissions: write-all` or `id-token: write`.
func grantsIDToken(p *yaml.Node) bool {
	if p == nil {
		return false
	}
	if p.Kind == yaml.ScalarNode {
		return p.Value == "write-all"
	}
	return scalar(mapGet(p, "id-token")) == "write"
}

func stepsOf(job *yaml.Node) []*yaml.Node {
	seq := mapGet(job, "steps")
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]*yaml.Node, 0, len(seq.Content))
	for _, c := range seq.Content {
		if c = deref(c); c.Kind == yaml.MappingNode {
			out = append(out, c)
		}
	}
	return out
}

// deref follows a YAML alias to its anchor.
func deref(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

// mapGetKey returns the key node for key in mapping m, or nil.
func mapGetKey(m *yaml.Node, key string) *yaml.Node {
	if m = deref(m); m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i]
		}
	}
	return nil
}

// mapGet returns the value node for key in mapping m, or nil.
func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m = deref(m); m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return deref(m.Content[i+1])
		}
	}
	return nil
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// nodeText concatenates every scalar under n, for "does this mention X".
func nodeText(n *yaml.Node) string {
	n = deref(n)
	if n == nil {
		return ""
	}
	if n.Kind == yaml.ScalarNode {
		return n.Value
	}
	var b strings.Builder
	for _, c := range n.Content {
		b.WriteString(nodeText(c))
		b.WriteByte('\n')
	}
	return b.String()
}
