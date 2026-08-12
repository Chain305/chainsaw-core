package hook

// Opt-in repair for a config whose chainsaw markers no longer form a
// well-formed block (H9).
//
// The failure it addresses: a user deletes the `# <<< chainsaw-managed <<<`
// line while debugging. Every subsequent `install-hook` then appends a fresh
// block (four runs measured four start markers and four registry= lines),
// Status reports not-wired, and Unwire fails forever.
//
// The rejected fix was to treat "start marker → EOF" as the block and replace
// it silently. That deletes every user line after the marker — and our block
// is appended at END OF FILE, so "after the marker" is precisely where a
// user's later additions live. It also contradicts a deliberate, comment-
// documented, test-pinned refusal (sentinel.go's findMarkedLines,
// sentinel_test.go's "only start" and "two starts before end (corrupt)"
// cases).
//
// So: Wire REFUSES (checkSentinelIntegrity), and the destructive path is a
// separate, explicit verb that shows the operator exactly which lines it
// would delete and asks first.

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrRepairUnsupported is returned by PlanRepair for managers whose config is
// not a sentinel-delimited text file (maven, nuget, docker).
var ErrRepairUnsupported = errors.New("repair is not supported for this manager")

// ErrNothingToRepair is returned when the config carries no malformed block.
var ErrNothingToRepair = errors.New("no malformed chainsaw block found")

// RepairLine is one line a repair would delete, with its 1-based number.
type RepairLine struct {
	Number int
	Text   string
}

// RepairPlan is the preview for a single config file.
type RepairPlan struct {
	Path  string
	Lines []RepairLine
}

// repairable is implemented by managers whose config uses a sentinel block.
// Managers that do not implement it get ErrRepairUnsupported.
type repairable interface {
	repairTargets(scope Scope) ([]string, markerClassifier, error)
}

func (m npmManager) repairTargets(scope Scope) ([]string, markerClassifier, error) {
	p, err := m.ConfigPathForScope(scope)
	return []string{p}, hashMarker, err
}

func (m yarnManager) repairTargets(scope Scope) ([]string, markerClassifier, error) {
	p, err := m.ConfigPathForScope(scope)
	return []string{p}, hashMarker, err
}

func (m bunManager) repairTargets(scope Scope) ([]string, markerClassifier, error) {
	p, err := m.ConfigPathForScope(scope)
	return []string{p}, hashMarker, err
}

func (m pipManager) repairTargets(scope Scope) ([]string, markerClassifier, error) {
	p, err := m.ConfigPathForScope(scope)
	return []string{p}, hashMarker, err
}

func (m cargoManager) repairTargets(scope Scope) ([]string, markerClassifier, error) {
	p, err := m.ConfigPathForScope(scope)
	return []string{p}, hashMarker, err
}

func (m goModManager) repairTargets(scope Scope) ([]string, markerClassifier, error) {
	p, err := m.ConfigPathForScope(scope)
	return []string{p}, hashMarker, err
}

func (m gradleManager) repairTargets(scope Scope) ([]string, markerClassifier, error) {
	p, err := m.ConfigPathForScope(scope)
	return []string{p}, gradleMarker, err
}

func (m sbtManager) repairTargets(scope Scope) ([]string, markerClassifier, error) {
	repos, err := sbtRepositoriesPath(scope)
	if err != nil {
		return nil, hashMarker, err
	}
	creds, err := sbtCredentialsPath(scope)
	if err != nil {
		return nil, hashMarker, err
	}
	env, err := sbtCoursierEnvPath(scope)
	if err != nil {
		return nil, hashMarker, err
	}
	return []string{repos, creds, env}, hashMarker, nil
}

// PlanRepair reports exactly which lines a repair would delete from the
// manager's config for the given scope. Returns ErrNothingToRepair when every
// target file is either absent, clean, or carries a well-formed block.
func PlanRepair(m Manager, scope Scope) ([]RepairPlan, error) {
	r, ok := m.(repairable)
	if !ok {
		return nil, fmt.Errorf("%w: %s config is not a sentinel-delimited text file; edit it by hand", ErrRepairUnsupported, m.Name())
	}
	paths, classify, err := r.repairTargets(scope)
	if err != nil {
		return nil, err
	}
	var plans []RepairPlan
	for _, p := range paths {
		data, err := readOrEmpty(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		if len(data) == 0 {
			continue
		}
		if corrupt, _ := sentinelCorrupt(data, classify); !corrupt {
			continue
		}
		lines, _ := splitLines(data)
		var doomed []RepairLine
		for _, idx := range planRepairLines(lines, classify) {
			doomed = append(doomed, RepairLine{Number: idx + 1, Text: lines[idx]})
		}
		if len(doomed) == 0 {
			continue
		}
		plans = append(plans, RepairPlan{Path: p, Lines: doomed})
	}
	if len(plans) == 0 {
		return nil, ErrNothingToRepair
	}
	return plans, nil
}

// planRepairLines returns the sorted indices of every line that belongs to a
// malformed chainsaw region.
//
// A start marker consumes through the next end marker; a start with no end
// consumes to EOF (this is chainsaw's own append-at-EOF block, truncated by a
// hand edit). A stray end marker with no start consumes only itself.
func planRepairLines(lines []string, classify markerClassifier) []int {
	var out []int
	for i := 0; i < len(lines); i++ {
		switch classify(lines[i]) {
		case markerStart:
			end := len(lines) - 1
			for j := i + 1; j < len(lines); j++ {
				if classify(lines[j]) == markerEnd {
					end = j
					break
				}
			}
			for k := i; k <= end; k++ {
				out = append(out, k)
			}
			i = end
		case markerEnd:
			out = append(out, i)
		}
	}
	return out
}

// ApplyRepair deletes exactly the lines PlanRepair reported. Callers must
// show the plan and obtain confirmation first; this function does not prompt.
func ApplyRepair(m Manager, scope Scope, plans []RepairPlan) error {
	r, ok := m.(repairable)
	if !ok {
		return fmt.Errorf("%w: %s", ErrRepairUnsupported, m.Name())
	}
	_, classify, err := r.repairTargets(scope)
	if err != nil {
		return err
	}
	for _, plan := range plans {
		data, err := readOrEmpty(plan.Path)
		if err != nil {
			return fmt.Errorf("read %s: %w", plan.Path, err)
		}
		nl := detectNewline(data)
		lines, trailingNL := splitLines(data)
		// Re-derive the plan and require it to match what we showed the
		// user; the file may have changed since the preview.
		fresh := planRepairLines(lines, classify)
		if !samePlan(fresh, lines, plan.Lines) {
			return fmt.Errorf("%s changed since the preview was generated; re-run the repair", plan.Path)
		}
		doomed := make(map[int]bool, len(fresh))
		for _, idx := range fresh {
			doomed[idx] = true
		}
		kept := make([]string, 0, len(lines))
		for i, ln := range lines {
			if !doomed[i] {
				kept = append(kept, ln)
			}
		}
		if _, err := backup(plan.Path); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
		if strings.TrimSpace(strings.Join(kept, "")) == "" {
			if err := os.Remove(plan.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove %s: %w", plan.Path, err)
			}
			continue
		}
		var buf strings.Builder
		for i, ln := range kept {
			buf.WriteString(ln)
			if i < len(kept)-1 || trailingNL {
				buf.WriteString(nl)
			}
		}
		if err := writeAtomic(plan.Path, []byte(buf.String())); err != nil {
			return err
		}
	}
	return nil
}

func samePlan(fresh []int, lines []string, shown []RepairLine) bool {
	if len(fresh) != len(shown) {
		return false
	}
	for i, idx := range fresh {
		if idx+1 != shown[i].Number || lines[idx] != shown[i].Text {
			return false
		}
	}
	return true
}
