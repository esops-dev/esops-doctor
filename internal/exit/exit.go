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
