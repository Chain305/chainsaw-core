//go:build selfhosted

package telemetry

// Self-hosted build tag: operators compile chainsaw with
// `go build -tags selfhosted ...` and the binary treats telemetry as
// opt-in. See consent.go for the resolution order.
const defaultSelfHosted = true
