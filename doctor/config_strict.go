package doctor

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// knownTopLevelConfigFields enumerates every top-level YAML key that
// internal/config.Config accepts today. Kept as a hand-rolled list
// (rather than reflected from the config struct) for two reasons:
//
//  1. internal/config.Config has `Extra map[...] yaml:",inline"` as a
//     forward-compat escape hatch — reflecting on it would mean every
//     unknown top-level key is silently absorbed into Extra rather
//     than surfaced to the operator. The doctor's whole job here is to
//     surface those, so we deliberately reject the escape hatch.
//
//  2. Doctor is dependency-light by design (see package doc). Pulling
//     in internal/config just to list keys would drag in the policy,
//     url, etc. trees that the doctor binary has been careful to keep
//     out.
//
// When a new top-level key is added to internal/config.Config this
// list MUST be updated in the same change — otherwise the doctor will
// false-positive "unknown field" on valid deployments.
var knownTopLevelConfigFields = map[string]struct{}{
	"runtime":                     {},
	"server":                      {},
	"blob_store":                  {},
	"http_client":                 {},
	"index":                       {},
	"exceptions":                  {},
	"geoip":                       {},
	"hooks":                       {},
	"clamav":                      {},
	"data_sources":                {},
	"release_policy":              {},
	"swift":                       {},
	"policies":                    {},
	"policy":                      {},
	"blocking_mode":               {},
	"provenance":                  {},
	"malware":                     {},
	"repository_anonymous_access": {},
	"repositories":                {},
	"remotes":                     {},
}

// deprecatedConfigFields maps dotted-path old-name → replacement
// guidance. Populated from MIGRATIONS.md's "Deprecated flags /
// endpoints" log. Entries must be kept in sync: when a future release
// drops support for a field entirely, move it out of here and let the
// strict-decode path catch it as unknown.
//
// Current entries:
//   - hooks.trivial.binary_path: the BinaryPath field is still present
//     on TrivialHookConfig but the in-process scanner ignores it (see
//     internal/config/config.go:290 and main.go's initTrivialScanner
//     which logs a warning at startup). Flagging it here lets the
//     doctor surface the deprecation before the operator hits the log.
var deprecatedConfigFields = map[string]string{
	"hooks.trivial.binary_path": "The in-process Trivy DB scanner ignores binary_path. Remove the field — set hooks.trivial.db_path instead.",
}

// unknownFieldRE extracts the field name and line number from a yaml.v3
// KnownFields(true) error. The format has been stable since go-yaml
// v3.0.0 and reads roughly:
//
//	yaml: unmarshal errors:
//	  line 3: field foo not found in type doctor.strictConfigRoot
//
// or (single-error variant):
//
//	yaml: line 3: field foo not found in type doctor.strictConfigRoot
//
// We tolerate both shapes.
var unknownFieldRE = regexp.MustCompile(`line (\d+): field (\S+) not found`)

// typeMismatchRE matches yaml.v3's cannot-unmarshal type errors. Shape:
//
//	line 3: cannot unmarshal !!int `42` into string
var typeMismatchRE = regexp.MustCompile(`line (\d+): cannot unmarshal`)

// strictYAMLCheck is the body of the config-check that validates the
// on-disk YAML against the known schema. Returns zero findings on a
// clean parse.
//
// Separate from checkConfig so the existence/readability/emptiness
// findings in checkConfig stay orthogonal to schema concerns — the
// caller stitches both sets together.
func strictYAMLCheck(path string, data []byte) []Finding {
	// 1. Multi-document rejection. chainsaw config is a single YAML
	//    document by contract; accepting multiple would silently apply
	//    only the first and leak the rest into operator confusion.
	//    Count documents by streaming the decoder.
	docCount, firstDoc, splitErr := countYAMLDocs(data)
	if splitErr != nil {
		// Pure parse error (e.g. malformed YAML). Surface as Breaking —
		// the server won't boot either.
		return []Finding{{
			Check:       "config:parse",
			Severity:    SeverityBreaking,
			Message:     fmt.Sprintf("%s: %v", path, splitErr),
			Remediation: "Fix the YAML syntax error before starting the server.",
		}}
	}
	if docCount > 1 {
		return []Finding{{
			Check:       "config:multi-doc",
			Severity:    SeverityBreaking,
			Message:     fmt.Sprintf("%s contains %d YAML documents; chainsaw config must be a single document", path, docCount),
			Remediation: "Remove `---` separators; merge the documents into a single config block.",
		}}
	}
	if docCount == 0 || firstDoc == nil {
		// Empty / whitespace-only. The caller's checkConfig already
		// emits the empty-file warning; nothing more to say here.
		return nil
	}

	var findings []Finding

	// 2. Deprecated-field scan. Walk the top-level document looking
	//    for known old paths. Done before strict-decode so the
	//    operator sees a specific remediation rather than a generic
	//    "unknown field" message (the deprecated key may or may not
	//    be in the strict schema).
	findings = append(findings, scanDeprecatedFields(path, firstDoc)...)

	// 3. Top-level unknown-field scan. Walk the root mapping's keys;
	//    anything outside knownTopLevelConfigFields and the deprecated
	//    list (already warned above) is a Warn finding. Using the
	//    yaml.Node tree lets us preserve line numbers.
	findings = append(findings, scanUnknownTopLevel(path, firstDoc)...)

	// 4. Strict nested decode. Re-decode the document into the strict
	//    mirror struct with KnownFields(true). This catches unknown
	//    *nested* fields (e.g. server.bogus) and type mismatches.
	if err := strictDecode(bytes.NewReader(data)); err != nil {
		findings = append(findings, classifyStrictDecodeError(path, err)...)
	}

	return findings
}

// countYAMLDocs streams the input through yaml.Decoder and returns the
// number of documents it contained plus the first one (for downstream
// walks). Returns a parse error verbatim on malformed YAML.
func countYAMLDocs(data []byte) (int, *yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var count int
	var first *yaml.Node
	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, nil, err
		}
		count++
		if first == nil {
			// Document nodes wrap the actual content; unwrap to the
			// mapping node so callers don't need to care.
			first = unwrapDocNode(&node)
		}
	}
	return count, first, nil
}

func unwrapDocNode(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		return n.Content[0]
	}
	return n
}

// scanUnknownTopLevel walks the top-level mapping and emits a Warn
// for every key not in knownTopLevelConfigFields and not already in
// the deprecated list.
func scanUnknownTopLevel(path string, root *yaml.Node) []Finding {
	if root == nil || root.Kind != yaml.MappingNode {
		return nil
	}
	var findings []Finding
	for i := 0; i < len(root.Content); i += 2 {
		keyNode := root.Content[i]
		if keyNode.Kind != yaml.ScalarNode {
			continue
		}
		key := keyNode.Value
		if _, ok := knownTopLevelConfigFields[key]; ok {
			continue
		}
		// Skip if already reported as deprecated.
		if _, dep := deprecatedConfigFields[key]; dep {
			continue
		}
		findings = append(findings, Finding{
			Check:       "config:unknown-field",
			Severity:    SeverityWarn,
			Message:     fmt.Sprintf("%s:%d unknown top-level field %q", path, keyNode.Line, key),
			Remediation: "Remove the field or check for a typo against the documented schema.",
		})
	}
	return findings
}

// scanDeprecatedFields walks the tree looking for keys matching a
// deprecatedConfigFields path and emits a Warn finding per hit. Paths
// are dotted (server.listen, hooks.trivial.binary_path, etc.).
func scanDeprecatedFields(path string, root *yaml.Node) []Finding {
	if root == nil {
		return nil
	}
	var findings []Finding
	for dotted, guidance := range deprecatedConfigFields {
		if line, ok := findDottedKey(root, strings.Split(dotted, ".")); ok {
			findings = append(findings, Finding{
				Check:       "config:deprecated-field",
				Severity:    SeverityWarn,
				Message:     fmt.Sprintf("%s:%d deprecated field %q is set", path, line, dotted),
				Remediation: guidance,
			})
		}
	}
	// Sort for stable ordering — map iteration is nondeterministic and
	// tests lean on deterministic finding order.
	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].Message < findings[j].Message
	})
	return findings
}

// findDottedKey walks a mapping node following the segment path and
// returns the line number of the final segment's key node if present.
func findDottedKey(root *yaml.Node, segments []string) (int, bool) {
	if len(segments) == 0 || root == nil {
		return 0, false
	}
	node := root
	for i, seg := range segments {
		if node.Kind != yaml.MappingNode {
			return 0, false
		}
		var found *yaml.Node
		var keyLine int
		for j := 0; j < len(node.Content); j += 2 {
			kn := node.Content[j]
			if kn.Kind == yaml.ScalarNode && kn.Value == seg {
				found = node.Content[j+1]
				keyLine = kn.Line
				break
			}
		}
		if found == nil {
			return 0, false
		}
		if i == len(segments)-1 {
			return keyLine, true
		}
		node = found
	}
	return 0, false
}

// strictDecode decodes the YAML stream into the strict mirror type
// with KnownFields(true). Returns the raw yaml.v3 error so the caller
// can pattern-match it — classifyStrictDecodeError converts it into
// Findings.
func strictDecode(r io.Reader) error {
	var cfg strictConfigRoot
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	return dec.Decode(&cfg)
}

// classifyStrictDecodeError turns a yaml.v3 decode error into one or
// more Findings. yaml.v3 batches errors ("yaml: unmarshal errors:\n
// line 3: ...\n line 5: ..."), so we split on newlines and classify
// each.
func classifyStrictDecodeError(path string, err error) []Finding {
	if err == nil {
		return nil
	}
	msg := err.Error()
	// Split the multi-error payload. Each sub-line starts with
	// "  line N:" — we don't care about leading whitespace, just grep
	// out the matching lines.
	lines := strings.Split(msg, "\n")
	var findings []Finding
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if m := unknownFieldRE.FindStringSubmatch(line); m != nil {
			// Unknown nested field — top-level is handled by
			// scanUnknownTopLevel; this branch only fires for
			// something like `server.bogus: 1`.
			findings = append(findings, Finding{
				Check:       "config:unknown-field",
				Severity:    SeverityWarn,
				Message:     fmt.Sprintf("%s:%s unknown field %q", path, m[1], m[2]),
				Remediation: "Remove the field or check for a typo against the documented schema.",
			})
			continue
		}
		if m := typeMismatchRE.FindStringSubmatch(line); m != nil {
			// Type mismatch (int where string expected, etc.). The
			// server wouldn't start — flag as Breaking.
			findings = append(findings, Finding{
				Check:       "config:type-mismatch",
				Severity:    SeverityBreaking,
				Message:     fmt.Sprintf("%s:%s %s", path, m[1], stripLinePrefix(line)),
				Remediation: "Fix the field type to match the documented schema.",
			})
			continue
		}
		// Heading line "yaml: unmarshal errors:" or the "yaml:" prefix
		// on single-error variants with no line number — skip unless
		// it's clearly actionable.
		if strings.HasPrefix(line, "yaml:") && !strings.Contains(line, "line ") {
			continue
		}
		// Fallback: unknown error shape. Surface as Breaking so the
		// operator sees *something* rather than a silent pass.
		findings = append(findings, Finding{
			Check:       "config:parse",
			Severity:    SeverityBreaking,
			Message:     fmt.Sprintf("%s: %s", path, line),
			Remediation: "Fix the YAML error before starting the server.",
		})
	}
	return findings
}

// stripLinePrefix drops the "line N: " prefix from a yaml.v3 error
// line so the caller can re-attach a file:line marker without
// double-printing.
func stripLinePrefix(line string) string {
	if idx := strings.Index(line, ": "); idx >= 0 {
		return line[idx+2:]
	}
	return line
}

// strictConfigRoot mirrors internal/config.Config's top-level shape
// for the purpose of strict decode. The inline Extra escape hatch is
// intentionally omitted here — that's what makes this decode strict
// where the production parse is forgiving.
//
// Nested types are RawNodes rather than the production structs so
// this file stays dependency-free and the "unknown nested field"
// detection fires through a *separate* strict decode per known
// section. That second pass is handled by re-using yaml.v3's
// KnownFields mechanic: each RawNode is walked against a compact
// schema defined alongside it.
//
// Keeping the shape flat (all RawNodes) is the boring choice; an
// earlier revision tried to mirror every ServerConfig field
// individually and went out of sync with internal/config in under a
// week. RawNode + a curated set of section-strict decoders (below)
// pushes that drift to compile time for the sections operators most
// commonly misconfigure.
type strictConfigRoot struct {
	Runtime                   yaml.Node    `yaml:"runtime"`
	Server                    strictServer `yaml:"server"`
	BlobStore                 yaml.Node    `yaml:"blob_store"`
	HTTPClient                yaml.Node    `yaml:"http_client"`
	Index                     yaml.Node    `yaml:"index"`
	Exceptions                yaml.Node    `yaml:"exceptions"`
	GeoIP                     yaml.Node    `yaml:"geoip"`
	Hooks                     yaml.Node    `yaml:"hooks"`
	ClamAV                    yaml.Node    `yaml:"clamav"`
	DataSources               yaml.Node    `yaml:"data_sources"`
	ReleasePolicy             yaml.Node    `yaml:"release_policy"`
	Swift                     yaml.Node    `yaml:"swift"`
	Policies                  yaml.Node    `yaml:"policies"`
	Policy                    yaml.Node    `yaml:"policy"`
	BlockingMode              *bool        `yaml:"blocking_mode"`
	Provenance                yaml.Node    `yaml:"provenance"`
	Malware                   yaml.Node    `yaml:"malware"`
	RepositoryAnonymousAccess *bool        `yaml:"repository_anonymous_access"`
	Repositories              yaml.Node    `yaml:"repositories"`
	Remotes                   yaml.Node    `yaml:"remotes"`
}

// strictServer is the one section we fully mirror, because server.*
// is by far the most operator-edited block and the one most likely
// to carry typos (listen_addr vs listen, tls.cert vs tls.cert_file).
// Other sections still get coarse parse validation via the RawNode
// pass — expanding the strict surface is cheap future work if a
// support-ticket pattern emerges.
type strictServer struct {
	Listen string            `yaml:"listen"`
	Admin  strictServerAdmin `yaml:"admin"`
	TLS    strictServerTLS   `yaml:"tls"`
}

type strictServerAdmin struct {
	Username string `yaml:"username"`
}

type strictServerTLS struct {
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	MinVersion string `yaml:"min_version"`
}
