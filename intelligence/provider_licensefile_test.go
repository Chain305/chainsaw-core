package intelligence

import (
	"context"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// Licence heads as they open in the real files.
const (
	agplHead = "                    GNU AFFERO GENERAL PUBLIC LICENSE\n                       Version 3, 19 November 2007\n\n Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>\n"
	gpl3Head = "                    GNU GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n\n Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>\n Everyone is permitted to copy and distribute verbatim copies\n"
	gpl2Head = "                    GNU GENERAL PUBLIC LICENSE\n                       Version 2, June 1991\n\n Copyright (C) 1989, 1991 Free Software Foundation, Inc.,\n"
	lgpl3    = "                   GNU LESSER GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n\n  This version of the GNU Lesser General Public License incorporates\nthe terms and conditions of version 3 of the GNU General Public\nLicense, supplemented by the additional permissions listed below.\n"
	mitText  = "MIT License\n\nCopyright (c) 2021 Example\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the \"Software\"), to deal\n"
	apache2  = "                                 Apache License\n                           Version 2.0, January 2004\n                        http://www.apache.org/licenses/\n"
)

func TestIdentifyLicenseText(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"AGPL-3.0", agplHead, "AGPL-3.0-only"},
		{"GPL-3.0", gpl3Head, "GPL-3.0-only"},
		{"GPL-2.0", gpl2Head, "GPL-2.0-only"},
		{"LGPL-3.0 names the GPL in its second sentence", lgpl3, "LGPL-3.0-only"},
		{"GPL-3.0 closing pointer to the LGPL does not outrank the title",
			gpl3Head + "\n...use the GNU Lesser General Public License instead of this License.\n", "GPL-3.0-only"},
		{"MIT", mitText, "MIT"},
		{"Apache-2.0", apache2, "Apache-2.0"},
		{"MIT with a GPL'd bundled-notice section later", mitText + "\nThis product bundles foo, licensed under the GNU General Public License.\n", "MIT"},
		{"BSD-3-Clause", "Redistribution and use in source and binary forms, with or without\nmodification, are permitted provided that the following conditions are met:\n* Neither the name of the copyright holder\n", "BSD-3-Clause"},
		// go.chromium.org/chromiumos/infra/proto/go LICENSE, as shipped.
		{"BSD pasted as // comments", "// Copyright 2019 The ChromiumOS Authors\n// Use of this source code is governed by a BSD-style license that can be\n// found in the LICENSE file.\n//\n// Redistribution and use in source and binary forms, with or without\n// modification, are permitted provided that the following conditions are\n// met:\n//    * Neither the name of Google Inc. nor the names of its\n", "BSD-3-Clause"},
		// commons-jelly 1.0-beta-3 META-INF/LICENSE.txt: its BSD-like
		// redistribution clause must not outrank the title.
		{"Apache-1.1 in a * block", "/*\n * ====================================================================\n *\n * The Apache Software License, Version 1.1\n *\n * Copyright (c) 1999-2001 The Apache Software Foundation.  All rights\n * reserved.\n *\n * Redistribution and use in source and binary forms, with or without\n * modification, are permitted provided that the following conditions\n", "Apache-1.1"},
		{"proprietary text", "Copyright (c) Acme Corp. All rights reserved.\n", ""},
	} {
		if got := identifyLicenseText([]byte(tc.body)); got != tc.want {
			t.Errorf("%s: identifyLicenseText = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func runLicenseFile(t *testing.T, files map[string]string) *ArtifactScanSection {
	t.Helper()
	req := Request{Key: Key{Ecosystem: "pypi", Package: "x", Version: "1"}, Artifact: &ArtifactHandle{Bytes: buildNPMTarball(t, files)}}
	pr, err := newLicenseFileProvider().Run(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	return pr.Scan
}

func TestLicenseFileSelection(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string // "" with wantFound=false means no fact at all
		found bool
	}{
		{"sdist root AGPL (khoj-assistant shape)", map[string]string{
			"khoj-assistant-1.14.0/LICENSE":              agplHead,
			"khoj-assistant-1.14.0/src/khoj/__init__.py": "",
			"khoj-assistant-1.14.0/src/khoj/main.py":     "print(1)\n",
		}, "AGPL-3.0-only", true},
		{"bundled third-party licence below the root is ignored (gollum shape)", map[string]string{
			"lib/gollum.rb": "module Gollum; end\n",
			"lib/gollum/public/gollum/javascript/ace/LICENSE": gpl2Head,
			"README.md": "# gollum\n",
		}, "", false},
		{"Go module zip: root LICENSE wins, sub-package LICENSE ignored", map[string]string{
			"github.com/x/y@v1.0.0/LICENSE":     mitText,
			"github.com/x/y@v1.0.0/go.mod":      "module github.com/x/y\n",
			"github.com/x/y@v1.0.0/sub/LICENSE": gpl3Head,
		}, "MIT", true},
		{"LGPL project ships COPYING + COPYING.LESSER", map[string]string{
			"package/COPYING":        gpl3Head,
			"package/COPYING.LESSER": lgpl3,
			"package/index.js":       "",
		}, "LGPL-3.0-only", true},
		{"Rust dual licence is an OR of both", map[string]string{
			"crate-1.0.0/LICENSE-MIT":    mitText,
			"crate-1.0.0/LICENSE-APACHE": apache2,
			"crate-1.0.0/src/lib.rs":     "",
		}, "Apache-2.0 OR MIT", true},
		{"wheel PEP 639 licenses/ directory", map[string]string{
			"pkg/__init__.py":                        "",
			"pkg-1.0.dist-info/METADATA":             "Name: pkg\n",
			"pkg-1.0.dist-info/licenses/LICENSE.txt": gpl2Head,
		}, "GPL-2.0-only", true},
		{"license.js is code, not a licence file", map[string]string{
			"package/license.js": "module.exports = 'GNU GENERAL PUBLIC LICENSE Version 3'\n",
			"package/index.js":   "",
		}, "", false},
		{"unrecognised root licence is still a licence file", map[string]string{
			"package/LICENSE":  "Copyright (c) Acme Corp. All rights reserved.\n",
			"package/index.js": "",
		}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := runLicenseFile(t, tc.files)
			if !tc.found {
				if s != nil && len(s.LicenseFilePaths) > 0 {
					t.Fatalf("found licence files %v, want none", s.LicenseFilePaths)
				}
				return
			}
			if s == nil || len(s.LicenseFilePaths) == 0 {
				t.Fatalf("no licence file found")
			}
			if s.LicenseFileExpression != tc.want {
				t.Errorf("expression = %q, want %q (paths %v)", s.LicenseFileExpression, tc.want, s.LicenseFilePaths)
			}
		})
	}
}

// Through ProjectToRiskInput and the evaluator: which licence signals fire.
func TestLicenseFileProjection(t *testing.T) {
	fired := func(r *Report) map[string]bool {
		in := ProjectToRiskInput(r)
		out := map[string]bool{}
		for _, c := range risk.EvaluatePackage(in, risk.Options{}).DirectScore.Categories {
			for _, f := range c.FiredSignals {
				out[f.ID] = true
			}
		}
		return out
	}
	report := func(manifest, fileExpr string, paths ...string) *Report {
		r := &Report{Identity: IdentitySection{Ecosystem: "pypi", Package: "x", Version: "1"}}
		r.Metadata.LicenseExpression = manifest
		r.Scan.LicenseFileExpression = fileExpr
		r.Scan.LicenseFilePaths = paths
		return r
	}

	// Empty manifest, AGPL root file: copyleft is priced, "no licence" is not.
	got := fired(report("", "AGPL-3.0-only", "khoj-assistant-1.14.0/LICENSE"))
	for _, id := range []string{risk.SignalLicCopyleft, risk.SignalLicNonPermissive} {
		if !got[id] {
			t.Errorf("empty manifest + AGPL file: %s did not fire", id)
		}
	}
	for _, id := range []string{risk.SignalLicMissing, risk.SignalLicUnidentified, risk.SignalLicSPDXPresent} {
		if got[id] {
			t.Errorf("empty manifest + AGPL file: %s fired", id)
		}
	}

	// Rust's dual licence: an OR of permissive licences is a free choice,
	// not an ambiguity, so it costs nothing.
	got = fired(report("", "Apache-2.0 OR MIT", "crate-1.0.0/LICENSE-APACHE", "crate-1.0.0/LICENSE-MIT"))
	for _, id := range []string{risk.SignalLicAmbiguousClassifier, risk.SignalLicMissing, risk.SignalLicUnidentified, risk.SignalLicCopyleft, risk.SignalLicSPDXPresent} {
		if got[id] {
			t.Errorf("Apache-2.0 OR MIT from files: %s fired", id)
		}
	}

	// A declared, identified licence wins over the file.
	got = fired(report("MIT", "GPL-3.0-only", "package/LICENSE"))
	if got[risk.SignalLicCopyleft] || !got[risk.SignalLicSPDXPresent] {
		t.Errorf("declared MIT must win over a GPL file: %v", got)
	}

	// An unidentified manifest yields to an identified file.
	got = fired(report("SEE LICENSE IN LICENSE", "GPL-3.0-only", "package/LICENSE"))
	if !got[risk.SignalLicCopyleft] || got[risk.SignalLicUnidentified] {
		t.Errorf("unidentified manifest + GPL file: %v", got)
	}

	// A file nobody recognises proves a licence exists, so not "none declared".
	got = fired(report("", "", "package/LICENSE"))
	if got[risk.SignalLicMissing] || !got[risk.SignalLicUnidentified] || got[risk.SignalLicSPDXPresent] {
		t.Errorf("empty manifest + unrecognised file: want unidentified only, got %v", got)
	}

	// No licence file found leaves today's behaviour untouched.
	got = fired(report("", ""))
	if !got[risk.SignalLicMissing] {
		t.Errorf("no file: lic.missing should still fire, got %v", got)
	}
}
