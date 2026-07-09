// Package log is a no-op vendor of github.com/aquasecurity/trivy/pkg/log.
//
// Upstream Trivy wires a richer slog-based logger with per-package prefixes.
// Chainsaw's scan pipeline currently pipes parser warnings nowhere — the
// user-visible error is a single "parse X: err" line from the CLI layer.
// When we want per-parser diagnostic output, swap this for a real
// *slog.Logger and thread it in from the scan command.
//
// The surface below is the exact subset called by vendored parsers.
package log

// Attr mirrors slog.Attr's zero-value-usable shape so call sites like
// log.Err(err) and log.String("k", "v") compile without dragging log/slog
// into every vendored file.
type Attr struct {
	Key   string
	Value any
}

// Logger is the per-prefix logger type. All methods are no-ops.
type Logger struct{ prefix string }

// WithPrefix returns a Logger tagged with prefix. No-op under chainsaw.
func WithPrefix(prefix string) *Logger { return &Logger{prefix: prefix} }

// Debug drops the message. Kept as a method so call sites compile.
func (l *Logger) Debug(msg string, attrs ...Attr) {}

// Info drops the message.
func (l *Logger) Info(msg string, attrs ...Attr) {}

// Warn drops the message.
func (l *Logger) Warn(msg string, attrs ...Attr) {}

// Error drops the message.
func (l *Logger) Error(msg string, attrs ...Attr) {}

// Err produces an Attr bundling an error value. Matches upstream signature.
func Err(err error) Attr { return Attr{Key: "err", Value: err} }

// String produces a string-valued Attr.
func String(k, v string) Attr { return Attr{Key: k, Value: v} }

// Warn at the package level is used by upstream dependency.UID; keep for
// parity in case a future parser calls it.
func Warn(msg string, attrs ...Attr) {}
