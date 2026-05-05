// Package exit maps doctor errors to the documented exit codes.
// Sentinels live here so any package can mark an error without
// depending on cli; the binary's main maps them to a code.
package exit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
)

// ErrUsage is the marker for usage errors (bad flag value, unknown flag,
// missing required flag, invalid value passed to a flag validator). Use
// errors.Is(err, ErrUsage) to detect; map to exit code 2.
//
// Sentinel-by-marker rather than sentinel-by-prefix: errors created via
// Usage() match errors.Is(err, ErrUsage) but render without a "usage
// error:" prefix, so wrapping chains don't stutter the marker text in
// front of the human-readable message.
var ErrUsage = errors.New("usage error")

// ErrCatalog is the marker for rule-catalog load and validate failures.
// Per §10 of CLAUDE.md these map to exit code 21 — distinct from the
// findings-threshold exit (20) so CI can tell "rules broken" apart from
// "rules ran and flagged something".
var ErrCatalog = errors.New("rule catalog error")

// Cluster-side sentinels. probes.Connect wraps the upstream pkg/client
// sentinels with these so the exit-code mapping stays in this package
// without dragging pkg/client into the import graph outside probes/.
//
//   - ErrUnreachable: transport layer failed (DNS, TCP, TLS handshake) — exit 3
//   - ErrAuth: HTTP 401 from the cluster — exit 4
//   - ErrForbidden: HTTP 403 from the cluster — exit 5
//   - ErrUnknownProduct: GET / returned something we don't recognise — exit 10
var (
	ErrUnreachable    = errors.New("cluster unreachable")
	ErrAuth           = errors.New("authentication failed")
	ErrForbidden      = errors.New("authorization failed")
	ErrUnknownProduct = errors.New("cluster is neither Elasticsearch nor OpenSearch")
)

// ErrFindings is the marker for "rules ran and flagged at least one
// finding at or above the --fail-on threshold". Exit 20. Distinct from
// generic error (1) so CI can tell "the lint failed honestly" apart from
// "the tool itself broke".
var ErrFindings = errors.New("findings at or above --fail-on threshold")

// Code returns the documented exit code for err. Sentinels in this
// package take priority; context.Canceled (SIGINT/SIGTERM) maps to 130
// because we can't tell which signal fired from the cancelled context
// alone — a caller that cares (main, with the signal in hand) should use
// SignalCode instead. nil maps to 0; everything else falls through to 1.
// Additional sentinels (cluster unreachable, auth failed, etc.) will
// land here when the cluster-touching path is built.
func Code(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, ErrUsage):
		return 2
	case errors.Is(err, ErrUnreachable):
		return 3
	case errors.Is(err, ErrAuth):
		return 4
	case errors.Is(err, ErrForbidden):
		return 5
	case errors.Is(err, ErrUnknownProduct):
		return 10
	case errors.Is(err, ErrFindings):
		return 20
	case errors.Is(err, ErrCatalog):
		return 21
	case errors.Is(err, context.Canceled):
		return 130
	default:
		return 1
	}
}

// SignalCode returns the conventional Unix exit code for a delivered
// signal: 128 + signal number. SIGINT → 130, SIGTERM → 143. Other
// signals fall through to 1 because doctor doesn't install handlers for
// them — receiving one would be an unexpected state.
func SignalCode(sig os.Signal) int {
	switch sig {
	case syscall.SIGINT:
		return 130
	case syscall.SIGTERM:
		return 143
	default:
		return 1
	}
}

// Usage returns a usage error with the formatted message. Matches
// errors.Is(err, ErrUsage) without prefixing the user-facing message.
func Usage(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}

type usageError struct{ msg string }

func (e *usageError) Error() string        { return e.msg }
func (e *usageError) Is(target error) bool { return target == ErrUsage }

// Catalog returns a catalog error with the formatted message. Matches
// errors.Is(err, ErrCatalog) without prefixing the user-facing message.
func Catalog(format string, args ...any) error {
	return &catalogError{msg: fmt.Sprintf(format, args...)}
}

type catalogError struct{ msg string }

func (e *catalogError) Error() string        { return e.msg }
func (e *catalogError) Is(target error) bool { return target == ErrCatalog }

// Silent wraps err so the binary skips printing it to stderr. Used for
// errors that the underlying library (urfave/cli) already wrote — without
// this main would double-print. Wrapping preserves the chain, so
// errors.Is(err, ErrUsage) and Code(err) still work.
func Silent(err error) error {
	if err == nil {
		return nil
	}
	return &silentErr{err: err}
}

type silentErr struct{ err error }

func (e *silentErr) Error() string { return e.err.Error() }
func (e *silentErr) Unwrap() error { return e.err }

// IsSilent reports whether err was wrapped with Silent.
func IsSilent(err error) bool {
	var s *silentErr
	return errors.As(err, &s)
}
