package risk

// license_name_normalisation_test.go — P8-10.
//
// The defect: registries carry the licence NAME, the classifier expected an
// SPDX id, and the mismatch was TWO-WAY. Apache/MIT artifacts were reported
// license.unidentified (a -15 false positive on most of Maven Central), and
// EPL/MPL/LGPL artifacts were ALSO reported license.unidentified — a false
// NEGATIVE, because no license.copyleft tag reached the policy engine and a
// copyleft block rule therefore could not fire on a genuine copyleft
// dependency.
//
// Every string in the FP and FN tables below was taken verbatim from a real
// registry document. The Maven ones are the exact <name> strings carried by
// the artifacts in the 400-package benign corpus.

import (
	"reflect"
	"strings"
	"testing"
)

func hasTag(tags []LicenseTag, want LicenseTag) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

// TestLicenceNameFalsePositivesAreGone is the FP half. Every one of these
// resolved to [license.unidentified] before normalisation.
func TestLicenceNameFalsePositivesAreGone(t *testing.T) {
	cases := []struct {
		name string // verbatim registry string
		spdx string // what it must normalise to
	}{
		// The four strings the plan executed against Classify.
		{"The Apache Software License, Version 2.0", "Apache-2.0"},
		{"Apache License, Version 2.0", "Apache-2.0"},
		{"MIT License", "MIT"},

		// The rest of the Maven corpus's non-SPDX names.
		{"The Apache License, Version 2.0", "Apache-2.0"},
		{"Apache 2.0", "Apache-2.0"},
		{"The MIT License", "MIT"},

		// PyPI free-text.
		{"Apache License 2.0", "Apache-2.0"},
		{"3-Clause BSD License", "BSD-3-Clause"},
		{"ISC License", "ISC"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeLicenseExpression(tc.name); got != tc.spdx {
				t.Errorf("NormalizeLicenseExpression(%q) = %q, want %q", tc.name, got, tc.spdx)
			}
			tags := Classify(tc.name)
			if hasTag(tags, LicenseTagUnidentified) {
				t.Errorf("Classify(%q) still reports license.unidentified: %v — "+
					"this is the -15 false positive the wave exists to remove", tc.name, tags)
			}
			if len(tags) != 0 {
				t.Errorf("Classify(%q) = %v, want no tags at all: a permissive "+
					"licence written in words is still a permissive licence", tc.name, tags)
			}
		})
	}
}

// TestLicenceNameFalseNegativesAreGone is the FN half, and it is the one
// that matters for enforcement rather than for scoring: without the
// license.copyleft TAG, core/policy's LicenseCopyleft condition cannot
// match, so an operator's copyleft block rule silently passed a genuine
// copyleft dependency.
func TestLicenceNameFalseNegativesAreGone(t *testing.T) {
	cases := []struct {
		name     string
		spdx     string
		strength LicenseStrength
	}{
		// The plan's stated FN case.
		{"GNU Lesser General Public License", "LGPL", LicenseStrengthWeakCopyleft},

		// Live in the 70-artifact Maven corpus: h2database, junit,
		// jakarta.annotation-api and two more.
		{"Eclipse Public License v2.0", "EPL-2.0", LicenseStrengthWeakCopyleft},
		{"Eclipse Public License 1.0", "EPL-1.0", LicenseStrengthWeakCopyleft},
		{"MPL 2.0", "MPL-2.0", LicenseStrengthWeakCopyleft},
		{"EPL 2.0", "EPL-2.0", LicenseStrengthWeakCopyleft},

		// The strong half, which must not be mistaken for the weak one.
		{"GNU General Public License", "GPL", LicenseStrengthStrongCopyleft},
		{"GNU Affero General Public License", "AGPL", LicenseStrengthStrongCopyleft},
		{"GNU General Public License, Version 3.0", "GPL-3.0-only", LicenseStrengthStrongCopyleft},

		// PyPI, corpus-v1-rev4 rows socket.dev flags copyleft: free text
		// (genbase, lc-django-autoslug) and trove classifier names.
		{"GNU LGPL v3", "LGPL-3.0-only", LicenseStrengthWeakCopyleft},
		{"GNU Lesser General Public License (LGPL), Version 3", "LGPL-3.0-only", LicenseStrengthWeakCopyleft},
		{"GNU General Public License v3 (GPLv3)", "GPL-3.0-only", LicenseStrengthStrongCopyleft},
		{"GNU Affero General Public License v3 or later (AGPLv3+)", "AGPL-3.0-or-later", LicenseStrengthStrongCopyleft},
		{"GNU Library or Lesser General Public License (LGPL)", "LGPL", LicenseStrengthWeakCopyleft},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeLicenseExpression(tc.name); got != tc.spdx {
				t.Errorf("NormalizeLicenseExpression(%q) = %q, want %q", tc.name, got, tc.spdx)
			}
			tags := Classify(tc.name)
			if !hasTag(tags, LicenseTagCopyleft) {
				t.Errorf("Classify(%q) = %v — no license.copyleft, so an operator's "+
					"copyleft policy rule cannot fire on a genuine copyleft dependency", tc.name, tags)
			}
			if hasTag(tags, LicenseTagUnidentified) {
				t.Errorf("Classify(%q) = %v — still unidentified", tc.name, tags)
			}
			if got := LicenseStrengthOf(tc.name); got != tc.strength {
				t.Errorf("LicenseStrengthOf(%q) = %d, want %d", tc.name, got, tc.strength)
			}
		})
	}
}

// TestAlreadySPDXIsUntouched is the blast-radius guard. Normalisation only
// runs on an expression the SPDX parser REJECTS, so roughly 80% of the
// corpus — every npm/go/pypi row that already carried an id — must go
// through byte-identical code. If this breaks, the fix stopped being a
// narrow repair of the unparsed tail.
func TestAlreadySPDXIsUntouched(t *testing.T) {
	for _, expr := range []string{
		"MIT",
		"Apache-2.0",
		"BSD-3-Clause",
		"ISC",
		"0BSD",
		"MPL-2.0",
		"GPL-3.0-only",
		"BUSL-1.1",
		"Apache-2.0 AND MIT",
		"Apache-2.0 OR BSD-3-Clause",
		"BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0",
		"(MIT OR CC0-1.0)",
		"GPL-2.0-only WITH Classpath-exception-2.0",
	} {
		if got := NormalizeLicenseExpression(expr); got != expr {
			t.Errorf("NormalizeLicenseExpression(%q) = %q — an expression that "+
				"already parses must be returned byte-identical", expr, got)
		}
	}
}

// TestAmbiguousNamesStayUnidentified pins the conservatism. A name that
// does not determine a licence must NOT be guessed at: reporting
// "unidentified" is the honest answer and is what the operator needs to see.
func TestAmbiguousNamesStayUnidentified(t *testing.T) {
	for _, expr := range []string{
		"Dual License",  // says nothing at all
		"See LICENSE",   //
		"Proprietary",   //
		"NOASSERTION",   //
		"Free for all!", //
	} {
		tags := Classify(expr)
		if !hasTag(tags, LicenseTagUnidentified) {
			t.Errorf("Classify(%q) = %v — a name that does not determine a "+
				"licence must stay unidentified rather than be guessed", expr, tags)
		}
	}
}

// Bare BSD is still not GUESSED into a clause count — the expression keeps
// its own word — but the family is permissive whichever grant it is, so it
// is recognised rather than charged -15 as unidentified (2026-10-03; 9
// corpus-v1-rev4 rows). Same for the trove spelling.
func TestBareBSDIsAKnownPermissiveFamily(t *testing.T) {
	for _, expr := range []string{"BSD", "BSD License"} {
		if got := NormalizeLicenseExpression(expr); got != "BSD" {
			t.Errorf("NormalizeLicenseExpression(%q) = %q, want the family token BSD", expr, got)
		}
		if tags := Classify(expr); len(tags) != 0 {
			t.Errorf("Classify(%q) = %v, want no tags", expr, tags)
		}
	}
	if tags := Classify("BSD-like"); !hasTag(tags, LicenseTagUnidentified) {
		t.Errorf("Classify(BSD-like) = %v — not a BSD licence, must stay unidentified", tags)
	}
}

// Real license strings that fired license.unidentified on corpus-v1-rev4
// and name a licence a standard reading identifies.
func TestCorpusLicenceStringsIdentify(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"MIT/Apache-2.0", "MIT OR Apache-2.0"},
		{"GPLv3", "GPL-3.0-only"},
		{"GPL V3", "GPL-3.0-only"},
		{"GPLv2", "GPL-2.0-only"},
		{"GPL V2", "GPL-2.0-only"},
		{"GPL version 2", "GPL-2.0-only"},
		{"AGPL-3", "AGPL-3.0-only"},
		{"LGPLv3", "LGPL-3.0-only"},
		{"LGPLv2.1+", "LGPL"},
		{"GNU Lesser General Public License version 3", "LGPL-3.0-only"},
		{"Eclipse Public License - v 1.0", "EPL-1.0"},
		{"Eclipse Public License - v 2.0", "EPL-2.0"},
		{"Apache", "Apache-2.0"},
		{"APL2", "Apache-2.0"},
		{"EUPL", "EUPL"},
		{"License :: OSI Approved :: MIT License", "MIT"},
		{"http://aws.amazon.com/apache2.0/", "Apache-2.0"},
		{"https://opensource.org/licenses/MIT", "MIT"},
		{"http://www.apache.org/licenses/LICENSE-2.0", "Apache-2.0"},
		{"MIT License\n        \n        Copyright (c) 2020 Nv7\n        \n        Permission is hereby granted, free of charge, to any person obtaining a copy\n        of this software", "MIT"},
		{"The MIT License\n        \n        Copyright (c) 2025 Cloudbeds (http://cloudbeds.com)\n\n        Permission is hereby granted, free of charge, to any person obtaining a copy", "MIT"},
	}
	for _, tc := range cases {
		if got := NormalizeLicenseExpression(tc.raw); got != tc.want {
			t.Errorf("NormalizeLicenseExpression(%q) = %q, want %q", tc.raw, got, tc.want)
		}
		if hasTag(Classify(tc.raw), LicenseTagUnidentified) {
			t.Errorf("Classify(%q) still unidentified: %v", tc.raw, Classify(tc.raw))
		}
	}
	// URL and file references with no standard mapping stay unidentified.
	for _, raw := range []string{
		"https://github.com/dotnet/corefx/blob/master/LICENSE.TXT",
		"LICENSE.txt",
		"http://www.ingeniux.com",
		"SEE LICENSE IN LICENSE.md",
		"https://opensource.org/licenses/NotALicence",
		"Commercial",
		"UNLICENSED",
		"Public Domain",
	} {
		if !hasTag(Classify(raw), LicenseTagUnidentified) {
			t.Errorf("Classify(%q) = %v — no standard mapping, must stay unidentified", raw, Classify(raw))
		}
	}
	// "GNU " + shorthand (rev5: rubygems set_version "GNU LGPLv3").
	for raw, want := range map[string]string{
		"GNU LGPLv3": "LGPL-3.0-only", "GNU GPLv3": "GPL-3.0-only", "GNU AGPLv3": "AGPL-3.0-only",
	} {
		if got := NormalizeLicenseExpression(raw); got != want {
			t.Errorf("NormalizeLicenseExpression(%q) = %q, want %q", raw, got, want)
		}
	}
	// A versioned copyleft token SPDX does not know is copyleft, and only
	// that: not also unidentified.
	if tags := Classify("LGPL-3"); !hasTag(tags, LicenseTagCopyleft) || hasTag(tags, LicenseTagUnidentified) {
		t.Errorf("Classify(LGPL-3) = %v, want copyleft without unidentified", tags)
	}
	// The copyleft ones keep their class.
	for _, raw := range []string{"GPLv3", "AGPL-3", "LGPLv2.1+", "EUPL", "GNU LGPLv3", "GNU AGPLv3", "LGPL-3"} {
		if !hasTag(Classify(raw), LicenseTagCopyleft) {
			t.Errorf("Classify(%q) lost copyleft: %v", raw, Classify(raw))
		}
	}
}

// TestCompoundOperandsNormaliseIndividually covers the middle pass: a
// compound where one operand is an id and the other is a name.
func TestCompoundOperandsNormaliseIndividually(t *testing.T) {
	got := NormalizeLicenseExpression("MIT OR Apache License 2.0")
	if got != "MIT OR Apache-2.0" {
		t.Fatalf("got %q, want %q", got, "MIT OR Apache-2.0")
	}
	tags := Classify("MIT OR Apache License 2.0")
	if hasTag(tags, LicenseTagUnidentified) {
		t.Errorf("Classify = %v, still unidentified", tags)
	}
	if !hasTag(tags, LicenseTagAmbiguous) {
		t.Errorf("Classify = %v — two distinct families is genuinely ambiguous "+
			"and must keep saying so", tags)
	}
}

// TestFullLicenceTextIsIdentifiedByItsTitle covers the third pass. Two
// PyPI packages in the benign corpus put the entire licence BODY in the
// metadata field. Both were license.unidentified, and pandas additionally
// fired license.exception_present at -5 because containsWordWith matched
// the English word "with" in "with or without modification" — a WITH
// exception that does not exist.
func TestFullLicenceTextIsIdentifiedByItsTitle(t *testing.T) {
	pandas := "BSD 3-Clause License\n\nCopyright (c) 2008-2011, AQR Capital Management, LLC\n" +
		"All rights reserved.\n\nRedistribution and use in source and binary forms, with or without\n" +
		"modification, are permitted provided that the following conditions are met:\n"
	sglang := "Apache License\n                           Version 2.0, January 2004\n" +
		"                        http://www.apache.org/licenses/\n\n" +
		"   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION\n"

	if got := NormalizeLicenseExpression(pandas); got != "BSD-3-Clause" {
		t.Errorf("pandas body normalised to %q, want BSD-3-Clause", got)
	}
	if got := NormalizeLicenseExpression(sglang); got != "Apache-2.0" {
		t.Errorf("sglang body normalised to %q, want Apache-2.0", got)
	}
	if tags := Classify(pandas); len(tags) != 0 {
		t.Errorf("Classify(pandas body) = %v, want none — in particular NOT "+
			"license.exception_present, which was matching the word \"with\" in prose", tags)
	}
	if tags := Classify(sglang); len(tags) != 0 {
		t.Errorf("Classify(sglang body) = %v, want none", tags)
	}
}

// TestShortAliasesDoNotMatchFullTextHeads guards the third pass against
// being loose. "Apache License" and "MIT License" are two-token aliases;
// allowing a two-word head match against several kilobytes of unrelated
// prose would identify anything that happened to start with those words.
func TestShortAliasesDoNotMatchFullTextHeads(t *testing.T) {
	body := "MIT License Agreement Addendum\n\nThis document is NOT a licence grant. " +
		strings.Repeat("Filler text to push this past the length gate. ", 8)
	if got := NormalizeLicenseExpression(body); got != body {
		t.Errorf("a short alias matched a full-text head: got %q", got)
	}
}

// TestClassifyIsDeterministic — Classify walks maps internally. Two calls
// on the same input must produce the same ORDERED tag slice, or a report
// rendered twice shows its findings in a different order.
func TestClassifyIsDeterministic(t *testing.T) {
	for _, expr := range []string{
		"GNU Lesser General Public License",
		"Eclipse Public License v2.0",
		"MIT OR Apache License 2.0",
		"Apache-2.0 AND Commons-Clause",
	} {
		first := Classify(expr)
		for i := 0; i < 20; i++ {
			if got := Classify(expr); !reflect.DeepEqual(got, first) {
				t.Fatalf("Classify(%q) is not deterministic: %v then %v", expr, first, got)
			}
		}
	}
}
