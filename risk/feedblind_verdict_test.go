package risk

import "testing"

// TestFeedBlindMalwareVerdicts pins the verdicts the 2026-10-03 feed-blind
// work intends, on a malicious shape and on the benign shapes that bound it.
// Every row is evaluated with no malware feed: these are the facts a scan of
// the bytes alone produces.
func TestFeedBlindMalwareVerdicts(t *testing.T) {
	cases := []struct {
		name        string
		in          Input
		want        Verdict
		wantCeiling string
	}{
		{
			// Datadog shape: preinstall runs a beacon, index.js posts to a
			// webhook.
			name: "exfil sink used + malicious install script quarantines",
			in: Input{Ecosystem: "npm", Package: "x", Version: "1.0.0",
				HasInstallScript: true, InstallScriptFetchesRemote: true,
				MaliciousIOCKind: "exfil_host", MaliciousIOCCoupled: true, MaliciousIOCAtEntry: true},
			want: VerdictQuarantine, wantCeiling: CompoundSCExfilAtInstall,
		},
		{
			// The sink is in an ordinary module, not a file install or import
			// runs. Both primitives still warn; nothing quarantines.
			name: "exfil sink outside the install/import path does not quarantine",
			in: Input{Ecosystem: "npm", Package: "x", Version: "1.0.0",
				HasInstallScript: true, InstallScriptFetchesRemote: true,
				MaliciousIOCKind: "exfil_host", MaliciousIOCCoupled: true},
			want: VerdictWarn, wantCeiling: SignalSCExfilSinkUsed,
		},
		{
			name: "exfil sink used alone warns",
			in: Input{Ecosystem: "pypi", Package: "x", Version: "1.0.0",
				MaliciousIOCKind: "exfil_host", MaliciousIOCCoupled: true},
			want: VerdictWarn, wantCeiling: SignalSCExfilSinkUsed,
		},
		{
			// yt-dlp: names gofile.io in a list of sites, sends nothing from
			// that file. sc.exfil_sink_named warns this shape since
			// 2026-10-10, except past a download line.
			name: "exfil host named but not used stays allow on a popular package",
			in: Input{Ecosystem: "pypi", Package: "x", Version: "1.0.0",
				MaliciousIOCKind: "exfil_host", WeeklyDownloads: intp(5_000_000)},
			want: VerdictAllow,
		},
		{
			// esbuild / node-sass / canvas: an install hook, proxy env reads,
			// a download and a shell-out. All three npm install compounds fire;
			// their warn ceilings do not apply past a download line, so the
			// rollup alone decides.
			name: "popular binary installer is not ceilinged",
			in: Input{Ecosystem: "npm", Package: "x", Version: "1.0.0",
				HasInstallScript: true, EnvVarAccess: true, NetworkAccess: true, CapShell: true,
				LicenseSPDX: "MIT", LicenseTags: Classify("MIT"), WeeklyDownloads: intp(5_000_000)},
			want: VerdictAllow,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := EvaluatePackage(tc.in, Options{})
			if ev.Verdict != tc.want || ev.DirectScore.CeilingSignal != tc.wantCeiling {
				t.Fatalf("verdict=%s overall=%d ceiling=%q, want verdict=%s ceiling=%q",
					ev.Verdict, ev.DirectScore.Overall, ev.DirectScore.CeilingSignal, tc.want, tc.wantCeiling)
			}
		})
	}
}
