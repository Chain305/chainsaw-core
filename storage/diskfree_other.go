//go:build !unix

package storage

// diskFreeFraction is unknown off unix; the byte cap alone bounds the tier.
func diskFreeFraction(string) (float64, bool) { return 0, false }
