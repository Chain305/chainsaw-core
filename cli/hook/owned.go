package hook

// Ownership records for configs chainsaw cannot fence with a sentinel block.
//
// `bundle config set` rewrites ~/.bundle/config from scratch, `gem sources
// --add` rewrites ~/.gemrc, and `composer config` rewrites config.json and
// auth.json. Every one of them drops comments, so a comment sentinel tells us
// nothing after the user's next ordinary command. Ownership is therefore
// recorded OUT OF BAND, as docker does (dockerSidecarPath): <config>.chainsaw
// lists each key chainsaw wrote and a SHA-256 of the value it wrote there.
//
// Unwire removes a key only when the file still holds exactly the value we
// recorded. A key the user set themselves, or one they changed after we wrote
// it, is never touched. Hashes, not values: the credential must not be copied
// into a second file.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/chain305/chainsaw-core/cli/secureio"
)

type ownedRecord struct {
	// Entries maps a key chainsaw wrote to the SHA-256 of the value it wrote.
	Entries map[string]string `json:"entries"`
	// Original holds the lines chainsaw replaced, verbatim, so Unwire can put
	// them back (gem's default `:sources:` list).
	Original []string `json:"original,omitempty"`
	// Flags records boolean facts about what chainsaw changed (composer: it,
	// not the user, set "packagist.org": false).
	Flags map[string]bool `json:"flags,omitempty"`
}

func ownedSidecarPath(configPath string) string { return configPath + ".chainsaw" }

func valueHash(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// owns reports whether key currently holds the exact value chainsaw recorded.
func (r ownedRecord) owns(key, value string) bool {
	h, ok := r.Entries[key]
	return ok && h == valueHash(value)
}

func readOwned(configPath string) ownedRecord {
	rec := ownedRecord{}
	data, err := readOrEmpty(ownedSidecarPath(configPath))
	if err == nil && len(data) > 0 {
		_ = json.Unmarshal(data, &rec)
	}
	if rec.Entries == nil {
		rec.Entries = map[string]string{}
	}
	return rec
}

func writeOwned(configPath string, rec ownedRecord) error {
	out, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal chainsaw ownership record: %w", err)
	}
	if err := secureio.WriteFile(ownedSidecarPath(configPath), append(out, '\n')); err != nil {
		return fmt.Errorf("write chainsaw ownership record: %w", err)
	}
	return nil
}

func removeOwned(configPath string) error {
	if err := os.Remove(ownedSidecarPath(configPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove chainsaw ownership record: %w", err)
	}
	return nil
}
