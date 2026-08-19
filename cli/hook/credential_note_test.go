package hook

import (
	"os"
	"strings"
	"testing"
)

// credential_note_test.go — L-09.
//
// The audit: seven managers embed a plaintext secret. npm, bun and sbt claimed
// chainsaw "keeps this file at mode 0600"; pip and cargo told the user to
// "chmod 600" it (advice writeConfigFile has already acted on); maven wrote a
// cleartext <password> with no note at all. And on Windows tightenExistingFile
// returned immediately, so the 0600 claim had nothing behind it there.

// TestNoRendererClaimsAModeItDoesNotEnforce is the anti-drift guard. A rendered
// config body must never name a numeric permission mode, because we do not
// honour one everywhere: ScopeSystem configs are deliberately left 0644, and
// Windows has no POSIX mode bits at all. The guarantee is stated in words by
// credentialHeaderNote; only that helper may state it.
//
// Note this is about the CONFIG BODIES we write to disk. The interactive
// notify() line that reports an actual chmod is a different thing and is still
// allowed to name the mode it actually applied.
func TestNoRendererClaimsAModeItDoesNotEnforce(t *testing.T) {
	banned := []string{"0600", "chmod 600", "0644", "chmod 644"}
	for _, m := range All() {
		t.Run(m.Name(), func(t *testing.T) {
			for _, scope := range []Scope{ScopeUser, ScopeSystem} {
				sandboxHome(t)
				opts := testWireOpts()
				opts.Credentials = testCreds
				// ScopeSystem paths are root-owned in production; render at
				// user scope on disk but exercise both note variants through
				// the helper directly below.
				if err := m.Wire(opts); err != nil {
					t.Fatalf("Wire: %v", err)
				}
				for _, p := range managerPaths(t, m, ScopeUser) {
					b, err := os.ReadFile(p)
					if err != nil {
						t.Fatalf("read %s: %v", p, err)
					}
					for _, bad := range banned {
						if strings.Contains(string(b), bad) {
							t.Errorf("%s (scope=%s) writes a config body naming %q; "+
								"state the guarantee in words via credentialHeaderNote instead — "+
								"the numeric mode is not honoured on Windows or at system scope\n%s",
								p, scope, bad, b)
						}
					}
				}
			}
		})
	}
}

// TestCredentialNoteIsSharedAndScopeAware pins the two things the helper has to
// get right: it says nothing when there is no secret, and it does not repeat
// the owner-only promise for a machine-wide file that cannot keep it.
func TestCredentialNoteIsSharedAndScopeAware(t *testing.T) {
	t.Run("no credentials means no note", func(t *testing.T) {
		if got := credentialHeaderNote("somewhere", WireOpts{Scope: ScopeUser}); got != "" {
			t.Fatalf("a placeholder-only config got a secret warning: %q", got)
		}
		if got := credentialNoteXMLBody("somewhere", WireOpts{Scope: ScopeUser}); got != "" {
			t.Fatalf("a placeholder-only settings.xml got a secret warning: %q", got)
		}
	})

	t.Run("user scope promises owner-only", func(t *testing.T) {
		got := credentialHeaderNote("the token below", WireOpts{Credentials: testCreds, Scope: ScopeUser})
		if !strings.Contains(got, "restricts it to your user account") {
			t.Fatalf("user-scope note does not state the guarantee: %q", got)
		}
		if !strings.Contains(got, "the token below") {
			t.Fatalf("the note does not say where the secret is: %q", got)
		}
		for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
			if !strings.HasPrefix(line, "# ") {
				t.Fatalf("note line is not a comment: %q", line)
			}
		}
	})

	t.Run("system scope discloses instead of promising", func(t *testing.T) {
		got := credentialHeaderNote("the token below", WireOpts{Credentials: testCreds, Scope: ScopeSystem})
		if strings.Contains(got, "restricts it to your user account") {
			t.Fatalf("machine-wide config promises owner-only, which credentialFileMode "+
				"deliberately does not do (a 0600 /etc/npmrc breaks npm for every non-root user): %q", got)
		}
		if !strings.Contains(got, "readable by every user") {
			t.Fatalf("machine-wide config does not disclose who can read the secret: %q", got)
		}
	})

	t.Run("xml body carries no double hyphen", func(t *testing.T) {
		// An XML comment may not contain "--", and maven embeds this note
		// inside one. A sentence that grows a long CLI flag would produce an
		// unparseable settings.xml on every mvn run.
		got := credentialNoteXMLBody("the password below", WireOpts{Credentials: testCreds, Scope: ScopeUser})
		if strings.Contains(got, "--") {
			t.Fatalf("the XML note contains a two hyphen sequence, which breaks the comment: %q", got)
		}
	})
}

// TestEveryCredentialBearingManagerDisclosesTheSecret closes the maven gap
// directly: any manager that writes a secret must say so in the file.
func TestEveryCredentialBearingManagerDisclosesTheSecret(t *testing.T) {
	for _, m := range All() {
		t.Run(m.Name(), func(t *testing.T) {
			sandboxHome(t)
			opts := testWireOpts()
			opts.Credentials = testCreds
			if err := m.Wire(opts); err != nil {
				t.Fatalf("Wire: %v", err)
			}
			_, secret, err := parseCreds(testCreds)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range managerPaths(t, m, ScopeUser) {
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatalf("read %s: %v", p, err)
				}
				body := string(b)
				// Only files that actually carry the secret need the note.
				if !strings.Contains(body, secret) && !strings.Contains(body, encodedTestSecretForms(secret, body)) {
					continue
				}
				if !strings.Contains(body, "chainsaw: this file contains a credential in cleartext") {
					t.Errorf("%s embeds the client secret with no disclosure note:\n%s", p, body)
				}
			}
		})
	}
}

// encodedTestSecretForms returns the secret as it appears in body when a
// manager encodes it (bun base64s the pair, pip percent-encodes it). Returns
// the plain secret when no encoded form is present, so the caller's Contains
// check simply falls through.
func encodedTestSecretForms(secret, body string) string {
	for _, enc := range []string{
		"Y2xpLWFiYzpzM2NyM3QtdmFsdWU=", // base64("cli-abc:s3cr3t-value"), bun
		"s3cr3t-value",                 // pip/cargo/sbt/maven write it raw
	} {
		if strings.Contains(body, enc) {
			return enc
		}
	}
	return secret
}
