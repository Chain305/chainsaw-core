//go:build !selfhosted

package telemetry

// defaultSelfHosted is the baked-in deployment mode. Cloud builds (the
// default) ship with this false — telemetry is opt-out. Self-hosted
// builds compile selfhosted_on.go instead via the `selfhosted` build
// tag and flip the default to true (opt-in).
const defaultSelfHosted = false
