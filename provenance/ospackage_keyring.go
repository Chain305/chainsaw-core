package provenance

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// Embedded default keyrings. Operators can drop armored (.asc) or binary
// (.gpg/.pgp) public-key files into internal/provenance/keys/apt or
// internal/provenance/keys/rpm; the loader picks up anything with those
// extensions at build time. The README.md files keep the go:embed glob
// satisfied when no keys have been vendored yet — the loader filters them
// out by extension. In practice chainsaw deployments point
// CHAINSAW_APT_KEYRING / CHAINSAW_RPM_KEYRING at a site-specific keyring.
//
//go:embed keys
var embeddedKeyrings embed.FS

// errKeyringEmpty is returned when neither the configured directory nor
// the embedded fallback yield any usable public keys. Callers treat this
// as StatusInconclusive rather than StatusFailed — "we couldn't evaluate
// trust" is distinct from "we evaluated trust and it failed".
var errKeyringEmpty = errors.New("no trusted keys available for this repo")

// loadKeyring reads public keys from the configured keyring path, falling
// back to the embedded snapshot when the path is unset, unreadable, or
// empty. Armored (.asc) and binary (.gpg) public keyrings are both
// accepted. A single directory is walked one level deep — APT's
// /etc/apt/trusted.gpg.d/ convention.
func loadKeyring(keyringPath, embeddedSubdir string) (openpgp.EntityList, error) {
	var keys openpgp.EntityList

	if keyringPath != "" {
		fsKeys, err := loadKeyringFromPath(keyringPath)
		if err != nil {
			// Path was configured but didn't yield keys. Continue to
			// embedded fallback so an operator typo doesn't silently
			// brick provenance verification for the whole fleet.
			if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("keyring %q: %w", keyringPath, err)
			}
		}
		keys = append(keys, fsKeys...)
	}

	if len(keys) == 0 {
		embedKeys, err := loadEmbeddedKeyring(embeddedSubdir)
		if err != nil {
			return nil, err
		}
		keys = append(keys, embedKeys...)
	}

	if len(keys) == 0 {
		return nil, errKeyringEmpty
	}
	return keys, nil
}

// loadKeyringFromPath reads a file or a directory (one level) of armored
// or binary public-key files.
func loadKeyringFromPath(p string) (openpgp.EntityList, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return readKeyringFile(p)
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	var all openpgp.EntityList
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".asc") && !strings.HasSuffix(name, ".gpg") && !strings.HasSuffix(name, ".pgp") {
			continue
		}
		entities, err := readKeyringFile(filepath.Join(p, e.Name()))
		if err != nil {
			// Skip unparseable key files rather than hard-fail; log
			// via the caller if needed.
			continue
		}
		all = append(all, entities...)
	}
	return all, nil
}

func readKeyringFile(path string) (openpgp.EntityList, error) {
	f, err := os.Open(path) // #nosec G304 — path comes from operator-configured trusted dir
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readKeyring(f)
}

func loadEmbeddedKeyring(subdir string) (openpgp.EntityList, error) {
	root := filepath.Join("keys", subdir)
	entries, err := embeddedKeyrings.ReadDir(root)
	if err != nil {
		// An empty embedded keyring is legitimate in early-adoption
		// deployments — return an empty list and let the caller fall
		// through to errKeyringEmpty.
		return nil, nil
	}
	var all openpgp.EntityList
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".asc") && !strings.HasSuffix(name, ".gpg") && !strings.HasSuffix(name, ".pgp") {
			continue
		}
		data, err := embeddedKeyrings.ReadFile(filepath.Join(root, e.Name()))
		if err != nil {
			continue
		}
		entities, err := readKeyring(bytes.NewReader(data))
		if err != nil {
			continue
		}
		all = append(all, entities...)
	}
	return all, nil
}

// readKeyring decodes either an ASCII-armored or a binary openpgp public
// keyring from r. Tries armored first and transparently retries in binary
// mode.
func readKeyring(r io.Reader) (openpgp.EntityList, error) {
	data, err := io.ReadAll(io.LimitReader(r, 16<<20)) // 16 MiB cap
	if err != nil {
		return nil, err
	}
	// Armored?
	if block, err := armor.Decode(bytes.NewReader(data)); err == nil && block != nil {
		if entities, err := openpgp.ReadKeyRing(block.Body); err == nil && len(entities) > 0 {
			return entities, nil
		}
	}
	// Binary.
	return openpgp.ReadKeyRing(bytes.NewReader(data))
}
