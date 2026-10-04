package codesmell

import (
	"regexp/syntax"
	"strings"
	"testing"
)

// TestEveryRuleAnchorIsInEveryMatch holds every registered rule (allRuleSets,
// so rule sets added later are covered without editing this test) to the
// prefilter contract: the rule's anchor must be inside every string the rule
// matches, or runRules skips a file the regex would have fired on.
//
// Matches are generated from the regex itself, at least one through every
// alternation branch and every optional piece taken and not taken, rather
// than from a hand list that rots. Each generated sample is first checked
// against the rule, so a generator gap shows up as a failure, never as a pass.
func TestEveryRuleAnchorIsInEveryMatch(t *testing.T) {
	if len(allRuleSets) < 7 {
		t.Fatalf("only %d rule sets registered; the registry is not being filled", len(allRuleSets))
	}
	checked := 0
	for _, s := range allRuleSets {
		for lang, rules := range s.ByLang {
			if s.Anchors[lang] != nil && len(s.Anchors[lang]) != len(rules) {
				t.Fatalf("lang %d: %d anchors for %d rules", lang, len(s.Anchors[lang]), len(rules))
			}
			for i, r := range rules {
				re, err := syntax.Parse(r.Re.String(), syntax.Perl)
				if err != nil {
					t.Fatal(err)
				}
				for _, sample := range regexSamples(re.Simplify()) {
					hit := sample
					if !r.Re.MatchString(hit) {
						hit = " " + sample + " "
					}
					if !r.Re.MatchString(hit) {
						t.Errorf("generator gap: %q does not match its own rule %s", sample, r.Re)
						continue
					}
					checked++
					if s.Anchors[lang] == nil {
						continue // no prefilter for this language: the regex runs on every file
					}
					if a := string(s.Anchors[lang][i]); !strings.Contains(hit, a) {
						t.Errorf("rule %s matches %q but its anchor %q is not in it: the prefilter skips this file", r.Re, hit, a)
					}
				}
			}
		}
	}
	if checked < 200 {
		t.Fatalf("only %d samples checked; the generator is not exercising the rules", checked)
	}
}

// regexSamples returns strings the regex matches, covering every alternation
// branch and both sides of every optional piece. Capped so a rule built from
// nested alternations cannot explode.
func regexSamples(re *syntax.Regexp) []string {
	const limit = 256
	switch re.Op {
	case syntax.OpLiteral:
		return []string{string(re.Rune)}
	case syntax.OpCharClass:
		return []string{string(classRune(re.Rune))}
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return []string{"x"}
	case syntax.OpCapture:
		return regexSamples(re.Sub[0])
	case syntax.OpStar, syntax.OpQuest:
		return append([]string{""}, regexSamples(re.Sub[0])...)
	case syntax.OpPlus:
		return regexSamples(re.Sub[0])
	case syntax.OpRepeat:
		sub := regexSamples(re.Sub[0])
		out := []string{}
		for _, s := range sub {
			out = append(out, strings.Repeat(s, re.Min))
		}
		return out
	case syntax.OpConcat:
		acc := []string{""}
		for _, sub := range re.Sub {
			next := regexSamples(sub)
			n := max(len(acc), len(next))
			if n > limit {
				n = limit
			}
			out := make([]string, n)
			for i := range out {
				out[i] = acc[i%len(acc)] + next[i%len(next)]
			}
			acc = out
		}
		return acc
	case syntax.OpAlternate:
		out := []string{}
		for _, sub := range re.Sub {
			out = append(out, regexSamples(sub)...)
		}
		if len(out) > limit {
			out = out[:limit]
		}
		return out
	}
	return []string{""} // zero-width assertions and empty matches
}

// classRune picks a printable member of a character class, so a negated class
// such as [^.\w$] yields a space rather than a control byte.
func classRune(ranges []rune) rune {
	for i := 0; i+1 < len(ranges); i += 2 {
		for r := ranges[i]; r <= ranges[i+1] && r < 0x7f; r++ {
			if r >= 0x20 {
				return r
			}
		}
	}
	return ranges[0]
}

// The three misses that found this: each line fires its signal.
func TestAnchorPrefilterRealMisses(t *testing.T) {
	for _, tc := range []struct {
		name string
		scan func(map[string][]byte) Result
		file string
		body string
	}{
		{"rust env::var", ScanEnvVars, "src/config.rs", "let home = std::env::var(\"HOME\").unwrap();\n"},
		{"python import socket", ScanNetwork, "agent/beacon.py", "import socket\ns = socket.create_connection((host, 443))\n"},
		{"php exec", ScanShell, "src/Runner.php", "<?php\n$out = exec(\"ls -la\");\n"},
		{"python urllib3", ScanNetwork, "client.py", "import urllib3\nhttp = urllib3.PoolManager()\n"},
		{"js import https", ScanNetwork, "index.mjs", "import https from 'node:https';\n"},
	} {
		if !tc.scan(map[string][]byte{tc.file: []byte(tc.body)}).Fired {
			t.Errorf("%s: did not fire on %q", tc.name, tc.body)
		}
	}
}
