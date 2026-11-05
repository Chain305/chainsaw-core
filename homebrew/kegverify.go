package homebrew

// Keg-vs-bottle comparison (brew verify --kegs).
//
// brew changes a bottle in exactly two ways when it pours it
// (keg_relocate.rb): text files get @@HOMEBREW_*@@ placeholders replaced by
// real paths, and Mach-O install names / rpaths that start with a
// placeholder are rewritten, after which the file is ad-hoc re-signed. So a
// poured file equals its bottle file byte for byte, or after placeholder
// substitution, or — for a relocated Mach-O — in MachOHash, which hashes
// everything except what relocation and re-signing legitimately change.
// The server computes these over the bottle; the CLI compares the disk.

import (
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"path"
	"strings"
)

// Relocation is where a keg's placeholders point on one machine.
type Relocation struct {
	Prefix string // HOMEBREW_PREFIX
	Perl   string // what @@HOMEBREW_PERL@@ became; "" leaves it in place
	Java   string // what @@HOMEBREW_JAVA@@ became; "" leaves it in place
}

// Replacer is brew's prepare_relocation_to_locations for r. Only the three
// standard prefixes are accepted: each fixes the repository location.
func (r Relocation) Replacer() (*strings.Replacer, error) {
	repo := r.Prefix
	switch r.Prefix {
	case "/opt/homebrew", "/home/linuxbrew/.linuxbrew":
	case "/usr/local":
		repo = "/usr/local/Homebrew"
	default:
		return nil, errors.New("prefix must be /opt/homebrew, /usr/local or /home/linuxbrew/.linuxbrew")
	}
	for _, p := range []string{r.Perl, r.Java} {
		if p != "" && (!path.IsAbs(p) || path.Clean(p) != p) {
			return nil, errors.New("perl and java must be clean absolute paths")
		}
	}
	pairs := []string{
		"@@HOMEBREW_PREFIX@@", r.Prefix,
		"@@HOMEBREW_CELLAR@@", r.Prefix + "/Cellar",
		"@@HOMEBREW_REPOSITORY@@", repo,
		"@@HOMEBREW_LIBRARY@@", repo + "/Library",
	}
	if r.Perl != "" {
		pairs = append(pairs, "@@HOMEBREW_PERL@@", r.Perl)
	}
	if r.Java != "" {
		pairs = append(pairs, "@@HOMEBREW_JAVA@@", r.Java)
	}
	return strings.NewReplacer(pairs...), nil
}

// HasPlaceholder reports whether b carries any brew relocation placeholder.
func HasPlaceholder(b []byte) bool { return bytes.Contains(b, []byte("@@HOMEBREW_")) }

// Mach-O load commands MachOHash treats specially.
const (
	lcSegment64     = 0x19
	lcCodeSignature = 0x1d
	lcLoadDylib     = 0xc
	lcIDDylib       = 0xd
	lcLazyLoadDylib = 0x20
	lcLoadWeakDylib = 0x80000018
	lcRpath         = 0x8000001c
	lcReexportDylib = 0x8000001f
	lcLoadUpward    = 0x80000023
)

// MachOHash is a hex sha256 of a thin 64-bit Mach-O that survives brew's
// relocation and re-signing and nothing else: the CPU and file type, every
// load command (install names and rpaths after rep, cmdsize ignored, the
// code-signature command and __LINKEDIT's sizes left out), and every byte
// from the first section up to the code signature. rep is nil for a file
// already on disk. "" for anything else (fat, 32-bit, not Mach-O, malformed):
// the caller then has only the raw hash to compare.
func MachOHash(b []byte, rep *strings.Replacer) string {
	f, err := macho.NewFile(bytes.NewReader(b))
	if err != nil || f.Magic != macho.Magic64 {
		return ""
	}
	defer f.Close()
	bo := f.ByteOrder
	h := sha256.New()
	put := func(p []byte) {
		var n [8]byte
		binary.LittleEndian.PutUint64(n[:], uint64(len(p)))
		h.Write(n[:])
		h.Write(p)
	}
	var hdr [12]byte
	bo.PutUint32(hdr[0:], uint32(f.Cpu))
	bo.PutUint32(hdr[4:], f.SubCpu)
	bo.PutUint32(hdr[8:], uint32(f.Type))
	put(hdr[:])

	sigOff := uint64(len(b))
	for _, l := range f.Loads {
		raw := l.Raw()
		if len(raw) < 8 {
			return ""
		}
		cmd := bo.Uint32(raw)
		switch cmd {
		case lcCodeSignature:
			if len(raw) < 16 {
				return ""
			}
			sigOff = uint64(bo.Uint32(raw[8:]))
			continue
		case lcIDDylib, lcLoadDylib, lcLoadWeakDylib, lcReexportDylib, lcLazyLoadDylib, lcLoadUpward, lcRpath:
			name, ok := lcString(raw, bo)
			if !ok {
				return ""
			}
			if rep != nil {
				name = rep.Replace(name)
			}
			put(raw[:4])
			put([]byte(name))
			if cmd != lcRpath && len(raw) >= 24 {
				put(raw[12:24]) // timestamp, current and compatibility version
			}
			continue
		case lcSegment64:
			if len(raw) >= 48 && strings.TrimRight(string(raw[8:24]), "\x00") == "__LINKEDIT" {
				put(raw[:4])
				put(raw[8:32])  // segname, vmaddr
				put(raw[40:48]) // fileoff
				continue
			}
		}
		c := append([]byte(nil), raw...)
		bo.PutUint32(c[4:], 0)
		put(c)
	}
	start := uint64(len(b))
	for _, s := range f.Sections {
		if s.Offset > 0 && uint64(s.Offset) < start {
			start = uint64(s.Offset)
		}
	}
	if start >= sigOff || sigOff > uint64(len(b)) {
		return ""
	}
	put(b[start:sigOff])
	return hex.EncodeToString(h.Sum(nil))
}

// lcString reads the lc_str at offset raw[8:12] of a dylib or rpath command.
func lcString(raw []byte, bo binary.ByteOrder) (string, bool) {
	if len(raw) < 12 {
		return "", false
	}
	off := bo.Uint32(raw[8:])
	if off < 12 || int(off) > len(raw) {
		return "", false
	}
	s := raw[off:]
	if i := bytes.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	return string(s), true
}
