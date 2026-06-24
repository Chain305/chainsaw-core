// Package dsl wraps the open-policy-agent rego runtime to expose a
// single decision query —
//
//	data.chainsaw.policy.decision
//
// — over the canonical chainsaw input shape (policy.Input). Built-in
// signals are already enforced natively by the Go evaluator; this
// package's role is the long tail of org-specific custom rules that
// platform engineers want to author once and apply at six surfaces.
//
// The engine is intentionally minimal: load a directory (or single
// file) of .rego sources at construction, compile + prepare the query
// once, evaluate per request. Hot-reload of bundles is handled by
// callers (the policyengine facade); the engine itself is immutable
// after New.
package dsl

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/chain305/chainsaw-core/policy"
)

// DefaultQuery is the entry point every chainsaw rule contributes to.
// Authors put one or more `decision := {...}` partial rules in a
// `package chainsaw.policy` module; the engine collects them all and
// reduces to the strictest action.
const DefaultQuery = "data.chainsaw.policy.decision"

// Action is the decision verb returned to the caller. Mirrors the
// existing policy.Mode enum so the policyengine facade can pick the
// strictest result across the Go and Rego paths without translating.
type Action string

const (
	ActionAllow      Action = "allow"
	ActionMonitor    Action = "monitor"
	ActionQuarantine Action = "quarantine"
	ActionBlock      Action = "block"
	// ActionNotifyOwner is a side-effect action introduced for Pain 4
	// (ownership routing). Unlike block/quarantine/monitor/allow it does
	// not gate the install — it ADDS a routing intent to the decision so
	// downstream surfaces can deliver the violation to the resolved
	// owning team's webhook destination. Strictness ranks BELOW monitor
	// (see strictness()) because the action carries no enforcement
	// semantics; a notify_owner verdict on its own should not flip an
	// otherwise-allow decision.
	ActionNotifyOwner Action = "notify_owner"
)

// strictness ranks actions for the "strictest wins" merge. Block beats
// quarantine beats monitor beats allow. Unknown actions sort below
// allow so a typo in a rule cannot escalate.
//
// ActionNotifyOwner is a SIDE-EFFECT action that ranks at the same level
// as allow: it carries no enforcement weight, so on its own it never
// promotes the decision past allow. The downstream router observes it
// via the Violation list (see engine_routing semantics in
// policyengine/engine.go) and fires the routing call.
func strictness(a Action) int {
	switch a {
	case ActionBlock:
		return 4
	case ActionQuarantine:
		return 3
	case ActionMonitor:
		return 2
	case ActionAllow:
		return 1
	case ActionNotifyOwner:
		return 1
	}
	return 0
}

// Stricter returns the more severe of two actions.
func Stricter(a, b Action) Action {
	if strictness(b) > strictness(a) {
		return b
	}
	return a
}

// Violation is one rule's contribution to the decision. The full set
// is returned so audit / UI surfaces can show "rule X fired because
// Y" instead of just "blocked".
//
// OwnerTeam / OwnerHandle / OwnerContactURL are populated when this
// violation participates in ownership routing (Pain 4). They flow into
// the webhook template context as `{{owner.team}}`, `{{owner.handle}}`,
// `{{owner.contact_url}}` — see internal/server/server_webhooks.go.
type Violation struct {
	RuleID            string `json:"ruleId,omitempty"`
	Action            Action `json:"action"`
	Message           string `json:"message,omitempty"`
	ExceptionEligible bool   `json:"exceptionEligible,omitempty"`
	// Owner-routing metadata. Empty when no team is resolved; the
	// downstream router treats unset fields as "no team known" and
	// falls back to the existing per-user webhook fan-out.
	OwnerTeam       string `json:"ownerTeam,omitempty"`
	OwnerHandle     string `json:"ownerHandle,omitempty"`
	OwnerContactURL string `json:"ownerContactUrl,omitempty"`
}

// Decision is the merged result returned to the caller.
type Decision struct {
	Action     Action      `json:"action"`
	Violations []Violation `json:"violations,omitempty"`
}

// Engine is a prepared, immutable Rego evaluator over the chainsaw
// policy bundle. Safe for concurrent Decide calls.
type Engine struct {
	prepared rego.PreparedEvalQuery
	digest   string // sha256 of the loaded source set, hex
	modules  []string
}

// Empty reports whether the engine has no rules loaded. Callers can
// short-circuit straight to the Go evaluator when this is true.
func (e *Engine) Empty() bool {
	return e == nil || len(e.modules) == 0
}

// Modules returns the file paths or logical names of the loaded Rego
// modules in stable order. Useful for audit logging the bundle that
// produced a decision.
func (e *Engine) Modules() []string {
	if e == nil {
		return nil
	}
	out := make([]string, len(e.modules))
	copy(out, e.modules)
	return out
}

// Digest returns a stable identifier for the loaded rule set. Callers
// stamp this on audit events so a decision is reproducible against a
// known bundle version.
func (e *Engine) Digest() string {
	if e == nil {
		return ""
	}
	return e.digest
}

// Options configures a new Engine.
type Options struct {
	// Sources lists either directory paths (recursively scanned for
	// *.rego) or individual .rego files. Nil / empty Sources produce
	// an empty engine that always returns ActionAllow.
	Sources []string

	// Query overrides the default decision query. Callers should
	// almost always leave this empty.
	Query string
}

// New compiles the rules at Options.Sources and prepares the
// decision query. Returns an empty engine (Empty()==true) when no
// .rego files are discovered — that lets callers wire the engine
// unconditionally and treat "no custom rules" as a no-op.
func New(ctx context.Context, opts Options) (*Engine, error) {
	files, err := discover(opts.Sources)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return &Engine{}, nil
	}

	q := opts.Query
	if q == "" {
		q = DefaultQuery
	}

	regoOpts := []func(*rego.Rego){rego.Query(q)}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read rego module %s: %w", f, err)
		}
		regoOpts = append(regoOpts, rego.Module(f, string(src)))
	}

	r := rego.New(regoOpts...)
	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compile rego bundle: %w", err)
	}

	return &Engine{
		prepared: pq,
		digest:   sourceDigest(files),
		modules:  files,
	}, nil
}

// Decide evaluates the prepared query against the input. An empty
// engine returns ActionAllow with no violations. Errors from the
// rego runtime are returned to the caller — the policyengine facade
// turns them into a fail-open allow-with-warning so a syntax error
// in a custom rule cannot block production traffic. That policy
// decision belongs in the facade, not here.
func (e *Engine) Decide(ctx context.Context, input policy.Input) (Decision, error) {
	if e.Empty() {
		return Decision{Action: ActionAllow}, nil
	}
	rs, err := e.prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return Decision{}, fmt.Errorf("eval rego: %w", err)
	}
	return reduce(rs), nil
}

// reduce projects a rego.ResultSet onto the merged Decision shape.
// The query value can be a single object (one rule fired), a set/
// array of objects (several rules fired), or empty (no rule fired —
// allow). Unknown shapes are tolerated as allow; defensive parsing
// here keeps a slightly mistyped rule from bubbling up as a runtime
// error.
func reduce(rs rego.ResultSet) Decision {
	out := Decision{Action: ActionAllow}
	for _, res := range rs {
		for _, expr := range res.Expressions {
			collectViolations(expr.Value, &out)
		}
	}
	// Stable order so audit logs / tests don't flake on map iteration.
	sort.SliceStable(out.Violations, func(i, j int) bool {
		if out.Violations[i].RuleID != out.Violations[j].RuleID {
			return out.Violations[i].RuleID < out.Violations[j].RuleID
		}
		return out.Violations[i].Message < out.Violations[j].Message
	})
	return out
}

func collectViolations(v any, out *Decision) {
	switch t := v.(type) {
	case map[string]any:
		viol, ok := violationFromMap(t)
		if !ok {
			return
		}
		out.Violations = append(out.Violations, viol)
		out.Action = Stricter(out.Action, viol.Action)
	case []any:
		for _, item := range t {
			collectViolations(item, out)
		}
	}
}

func violationFromMap(m map[string]any) (Violation, bool) {
	v := Violation{Action: ActionBlock}
	if a, ok := m["action"].(string); ok {
		v.Action = Action(strings.ToLower(strings.TrimSpace(a)))
	}
	if id, ok := m["rule_id"].(string); ok {
		v.RuleID = id
	} else if id, ok := m["ruleId"].(string); ok {
		v.RuleID = id
	}
	if msg, ok := m["message"].(string); ok {
		v.Message = msg
	}
	if e, ok := m["exception_eligible"].(bool); ok {
		v.ExceptionEligible = e
	} else if e, ok := m["exceptionEligible"].(bool); ok {
		v.ExceptionEligible = e
	}
	if v.Action == "" {
		return v, false
	}
	return v, true
}

// discover walks Sources and returns *.rego files in a deterministic
// order. Files are accepted directly; directories are walked
// recursively.
func discover(sources []string) ([]string, error) {
	var out []string
	for _, src := range sources {
		info, err := os.Stat(src)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		if !info.IsDir() {
			if strings.HasSuffix(src, ".rego") {
				out = append(out, src)
			}
			continue
		}
		err = filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, ".rego") {
				out = append(out, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	// dedupe
	seen := make(map[string]struct{}, len(out))
	uniq := out[:0]
	for _, p := range out {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		uniq = append(uniq, p)
	}
	return uniq, nil
}

// sourceDigest hashes the (path, content) pairs that make up the
// bundle so audit logs can name the exact rule set. Implementation
// is intentionally simple — sha256 over a canonical join — because
// the digest is for human reproducibility, not cryptographic
// integrity (signing rides outside this package).
var digestMu sync.Mutex

func sourceDigest(paths []string) string {
	digestMu.Lock()
	defer digestMu.Unlock()
	h := newHasher()
	for _, p := range paths {
		h.WriteString(p)
		h.WriteString("\x00")
		data, err := os.ReadFile(p)
		if err != nil {
			h.WriteString("err:")
			h.WriteString(err.Error())
			continue
		}
		h.Write(data)
		h.WriteString("\x01")
	}
	return h.Hex()
}
