package cli

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

// TestScanContextNoopOnZero asserts that --scan-timeout 0 (or unset
// to 0) is the documented "disable" path: scanContext returns the
// parent unmodified and a cancel that doesn't panic on call. The
// no-op cancel matters because every caller defers it.
func TestScanContextNoopOnZero(t *testing.T) {
	parent := context.Background()
	ctx, cancel := scanContext(parent, 0)
	if ctx != parent {
		t.Error("scanContext(0) should return parent unchanged")
	}
	cancel() // must not panic, must not error
}

// TestScanContextWrapsOnPositive confirms a positive timeout wraps
// the parent with a deadline. The wrapped context carries a deadline
// at most timeout into the future; we don't assert an exact value
// because clocks drift, only that one exists.
func TestScanContextWrapsOnPositive(t *testing.T) {
	parent := context.Background()
	ctx, cancel := scanContext(parent, 50*time.Millisecond)
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		t.Fatal("expected wrapped context to carry a deadline")
	}
	// Wait for the deadline to fire so we know the wrapping is
	// genuinely effective (not just present-but-inert).
	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Errorf("Done fired with non-deadline error: %v", ctx.Err())
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("wrapped context never fired its deadline")
	}
}

// TestScanContextNegativeIsNoop documents the boundary: a negative
// timeout is treated the same as zero (no wrap), because the runtime
// path validates the flag separately. This keeps scanContext small
// and removes the temptation to fail in two places.
func TestScanContextNegativeIsNoop(t *testing.T) {
	parent := context.Background()
	ctx, cancel := scanContext(parent, -1)
	defer cancel()
	if ctx != parent {
		t.Error("negative timeout should not wrap")
	}
}

// TestScanTimeoutFlagDefault asserts the default the flag advertises
// matches the documented constant. Drift here would silently change
// the safety ceiling on every scan.
func TestScanTimeoutFlagDefault(t *testing.T) {
	cmd := scanCommand()
	var dur *cli.DurationFlag
	for _, f := range cmd.Flags {
		df, ok := f.(*cli.DurationFlag)
		if !ok {
			continue
		}
		for _, n := range df.Names() {
			if n == "scan-timeout" {
				dur = df
			}
		}
	}
	if dur == nil {
		t.Fatal("--scan-timeout DurationFlag not registered on scan command")
	}
	if dur.Value != defaultScanTimeout {
		t.Errorf("flag default = %s, want %s", dur.Value, defaultScanTimeout)
	}
}

// TestScanTimeoutNegativeIsUsageError exercises the validation path
// in runScan: --scan-timeout -5s should bail with exit.ErrUsage
// before the connect ever happens. We don't need a real cluster
// because the validation runs before connectFn.
func TestScanTimeoutNegativeIsUsageError(t *testing.T) {
	err := newRoot().Run(context.Background(), []string{
		"esops-doctor", "scan", "--url", "http://nonexistent:9200", "--scan-timeout", "-5s",
	})
	if err == nil {
		t.Fatal("expected usage error for negative timeout")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("err is not ErrUsage: %v", err)
	}
}
