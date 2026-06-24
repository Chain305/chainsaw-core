package provenance

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// VerifyGemSignature verifies the legacy `gem cert` X.509 signing format
// used by RubyGems before Sigstore-based gem attestations existed.
//
// .gem files are tar archives whose entries include `metadata.gz`,
// `data.tar.gz`, and (when the gem was signed with `gem cert`) detached
// RSA signatures `metadata.gz.sig` and `data.tar.gz.sig` plus the
// signing certificate as a PEM block embedded in `metadata.gz` (older
// gems) or shipped alongside (newer gems). RubyGems uses RSA-SHA256 for
// modern signing keys and RSA-SHA1 for legacy ones — we try SHA-256
// first and fall back to SHA-1.
//
// Trust model: every successful verification carries a Warning making
// it explicit that the cert is gem-bundled and is NOT validated against
// any external trust root (RubyGems doesn't operate one). The signal is
// "the gem is internally consistent — bytes match the cert that ships
// with it." Continuity-of-identity must be enforced downstream by
// pinning SignerID across versions.
//
// Errors are returned only for unrecoverable conditions (the input
// isn't a tar archive at all). Missing signatures or missing certs
// produce Status=unavailable with a descriptive Warning so callers
// don't penalise the package for being unsigned.
func VerifyGemSignature(ctx context.Context, gemBytes []byte) (*Result, error) {
	files, err := readGemTar(gemBytes)
	if err != nil {
		return &Result{
			Status:    StatusUnavailable,
			Ecosystem: "rubygems",
			Warnings:  []string{"rubygems_gemcert_unparseable: " + err.Error()},
		}, nil
	}

	metadataGz, hasMetadata := files["metadata.gz"]
	metadataSig, hasMetadataSig := files["metadata.gz.sig"]
	dataTarGz, hasData := files["data.tar.gz"]
	dataSig, hasDataSig := files["data.tar.gz.sig"]
	checksumsGz, hasChecksums := files["checksums.yaml.gz"]
	checksumsSig, hasChecksumsSig := files["checksums.yaml.gz.sig"]

	if !hasMetadataSig && !hasDataSig && !hasChecksumsSig {
		return &Result{
			Status:    StatusUnavailable,
			Ecosystem: "rubygems",
			Warnings:  []string{"rubygems_gemcert_no_signature: gem has no .sig entries"},
		}, nil
	}

	cert, certErr := findSigningCert(files, metadataGz, hasMetadata)
	if certErr != nil {
		return &Result{
			Status:    StatusUnavailable,
			Ecosystem: "rubygems",
			Warnings:  []string{"rubygems_gemcert_no_signing_cert: " + certErr.Error()},
		}, nil
	}

	rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return &Result{
			Status:    StatusFailed,
			Ecosystem: "rubygems",
			Warnings:  []string{"rubygems_gemcert_unsupported_key: only RSA keys are supported"},
		}, nil
	}

	// Verify each (payload, signature) pair we have.
	var failures []string
	verifyPair := func(label string, payload, sig []byte) {
		if err := verifyRSASignature(rsaKey, payload, sig); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", label, err))
		}
	}
	if hasMetadata && hasMetadataSig {
		verifyPair("metadata.gz", metadataGz, metadataSig)
	}
	if hasData && hasDataSig {
		verifyPair("data.tar.gz", dataTarGz, dataSig)
	}
	if hasChecksums && hasChecksumsSig {
		verifyPair("checksums.yaml.gz", checksumsGz, checksumsSig)
	}

	signerID := certFingerprint(cert)
	builderID := certBuilderID(cert)

	if len(failures) > 0 {
		return &Result{
			Status:          StatusFailed,
			Ecosystem:       "rubygems",
			AttestationType: "x509-gemcert",
			BundleFormat:    "x509-detached",
			SignerID:        signerID,
			BuilderID:       builderID,
			Warnings: []string{
				"rubygems_gemcert_verification_failed: " + failures[0],
			},
			Error: failures[0],
		}, nil
	}

	return &Result{
		Status:          StatusVerified,
		Ecosystem:       "rubygems",
		AttestationType: "x509-gemcert",
		BundleFormat:    "x509-detached",
		SignerID:        signerID,
		BuilderID:       builderID,
		Warnings: []string{
			"x509 cert is gem-bundled; trust not validated against external root",
		},
	}, nil
}

// readGemTar reads the outer tar archive of a .gem file and returns
// its entries keyed by name. .gem files are NOT gzipped at the outer
// layer — only the inner metadata.gz / data.tar.gz / checksums.yaml.gz
// entries are individually gzipped, and we keep them in their gzipped
// form because that is the form the detached signatures sign.
func readGemTar(gemBytes []byte) (map[string][]byte, error) {
	tr := tar.NewReader(bytes.NewReader(gemBytes))
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		// Cap each entry at 256 MiB to match the Maven body cap.
		buf, err := io.ReadAll(io.LimitReader(tr, 256<<20))
		if err != nil {
			return nil, fmt.Errorf("read tar entry %q: %w", hdr.Name, err)
		}
		out[hdr.Name] = buf
	}
	if len(out) == 0 {
		return nil, errors.New("empty tar archive")
	}
	return out, nil
}

// findSigningCert locates the X.509 signing certificate. We check, in
// order:
//  1. A top-level `cert.pem` entry (newer convention).
//  2. Any tar entry name ending in `.pem` or `.crt`.
//  3. The decompressed contents of `metadata.gz` for an embedded PEM
//     block (older gems serialised the cert into the YAML manifest).
//
// We deliberately do NOT parse YAML — we just scan the bytes for the
// `-----BEGIN CERTIFICATE-----` marker and decode the first PEM block
// we find.
func findSigningCert(files map[string][]byte, metadataGz []byte, hasMetadata bool) (*x509.Certificate, error) {
	if pemBytes, ok := files["cert.pem"]; ok {
		if c, err := parseFirstCert(pemBytes); err == nil {
			return c, nil
		}
	}
	for name, body := range files {
		if name == "metadata.gz" || name == "data.tar.gz" || name == "checksums.yaml.gz" {
			continue
		}
		if len(name) >= 4 {
			suf := name[len(name)-4:]
			if suf == ".pem" || suf == ".crt" {
				if c, err := parseFirstCert(body); err == nil {
					return c, nil
				}
			}
		}
		// Some gems also stash the cert as `metadata.gz.sum` or in a
		// `*.gemspec` — try any entry that contains a PEM block.
		if bytes.Contains(body, []byte("-----BEGIN CERTIFICATE-----")) {
			if c, err := parseFirstCert(body); err == nil {
				return c, nil
			}
		}
	}
	if hasMetadata {
		raw, err := gunzip(metadataGz)
		if err == nil && bytes.Contains(raw, []byte("-----BEGIN CERTIFICATE-----")) {
			if c, err := parseFirstCert(raw); err == nil {
				return c, nil
			}
		}
	}
	return nil, errors.New("no PEM-encoded X.509 certificate found in gem")
}

// parseFirstCert walks PEM blocks until it finds a CERTIFICATE block
// and parses it. Tolerates leading whitespace / non-PEM noise (the
// metadata YAML wraps the PEM in a string field).
func parseFirstCert(b []byte) (*x509.Certificate, error) {
	rest := b
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
	// Fallback: trim to the first BEGIN CERTIFICATE marker and retry,
	// since YAML-embedded certs may be preceded by junk pem.Decode
	// silently skips but doesn't always handle.
	if idx := bytes.Index(b, []byte("-----BEGIN CERTIFICATE-----")); idx > 0 {
		block, _ := pem.Decode(b[idx:])
		if block != nil && block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
	return nil, errors.New("no CERTIFICATE PEM block")
}

// gunzip decompresses a gzip blob, capped at 256 MiB.
func gunzip(b []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	return io.ReadAll(io.LimitReader(gr, 256<<20))
}

// verifyRSASignature tries RSA-SHA256 first (modern gems) and falls
// back to RSA-SHA1 (legacy). Returns nil on the first match.
func verifyRSASignature(pub *rsa.PublicKey, payload, sig []byte) error {
	h256 := sha256.Sum256(payload)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h256[:], sig); err == nil {
		return nil
	}
	// Legacy SHA-1 fallback for older `gem cert` keys.
	h1 := sha1.Sum(payload)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, h1[:], sig); err == nil {
		return nil
	}
	return errors.New("signature does not match (tried RSA-SHA256 and RSA-SHA1)")
}

// certFingerprint returns the lowercase-hex SHA-256 of the DER-encoded
// certificate. This is the SignerID surfaced to operators for
// continuity-of-identity policy.
func certFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// certBuilderID returns a human-readable builder identity: the cert
// Subject CN if present, otherwise the first email SAN, otherwise the
// raw Subject DN string. Empty only when the cert has neither.
func certBuilderID(c *x509.Certificate) string {
	if cn := c.Subject.CommonName; cn != "" {
		return cn
	}
	if len(c.EmailAddresses) > 0 {
		return c.EmailAddresses[0]
	}
	return c.Subject.String()
}
