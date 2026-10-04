package codesmell

import "regexp"

// urlUserinfo is the userinfo part of a URL: scheme://user:secret@. It stops
// at '/', so a path containing '@' (npm scopes, git refs) is not touched.
var urlUserinfo = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^\s/?#@"'\x60<>]*@`)

// RedactURLCredentials replaces the userinfo of every URL in s with
// "REDACTED@". Snippets are copied out of shipped source files into stored
// and public reports, and a URL like https://user:ghp_...@github.com/x.git
// would carry the credential with it.
//
// Run it BEFORE any truncation: a cut between the secret and the '@' leaves
// nothing for the pattern to anchor on, and the secret survives.
func RedactURLCredentials(s string) string {
	return urlUserinfo.ReplaceAllString(s, "${1}REDACTED@")
}
