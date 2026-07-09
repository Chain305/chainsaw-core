# RPM embedded trust anchors

Drop Fedora/RHEL/CentOS RPM-GPG-KEY files here as `.asc` (ASCII-armored) or
`.gpg` (binary) public-key files. They will be compiled into the binary via
`go:embed` and used as a fallback keyring when `CHAINSAW_RPM_KEYRING` is
unset or its path is missing.

Operators who want to trust a specific distro release should prefer pointing
`CHAINSAW_RPM_KEYRING` at `/etc/pki/rpm-gpg/` inside a container or a
custom path, rather than relying on the embedded set, since embedded keys
age out with binary releases.

This directory ships empty by default — chainsaw deployments normally supply
their own keyring. See `provenance/yum_dnf.go` for the lookup order.
