package provenance

// This file used to house a stub osPackageChecker covering apt/dnf/yum
// with StatusUnavailable. The real backends now live in apt.go and
// yum_dnf.go — see those files for the hash-chain walkers.
//
// Kept as an empty file (intentionally not removed) so downstream
// branches that still reference internal/provenance/ospackage.go in
// their diffs have something coherent to rebase against. Remove on the
// next cleanup pass.
