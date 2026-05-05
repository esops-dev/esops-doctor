package exit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
)

func TestCodeNil(t *testing.T) {
	if got := Code(nil); got != 0 {
		t.Errorf("Code(nil) = %d, want 0", got)
	}
}

func TestCodeUsageDirect(t *testing.T) {
	if got := Code(ErrUsage); got != 2 {
		t.Errorf("Code(ErrUsage) = %d, want 2", got)
	}
}

func TestCodeUsageWrapped(t *testing.T) {
	err := fmt.Errorf("oops: %w", ErrUsage)
	if got := Code(err); got != 2 {
		t.Errorf("Code(wrapped ErrUsage) = %d, want 2", got)
	}
}

func TestCodeUsageHelper(t *testing.T) {
	err := Usage("--log-level %q is not supported", "trace")
	if !errors.Is(err, ErrUsage) {
		t.Error("Usage() error should be ErrUsage")
	}
	if got := Code(err); got != 2 {
		t.Errorf("Code(Usage) = %d, want 2", got)
	}
}

func TestCodeCanceled(t *testing.T) {
	if got := Code(context.Canceled); got != 130 {
		t.Errorf("Code(context.Canceled) = %d, want 130", got)
	}
}

func TestCodeOther(t *testing.T) {
	if got := Code(errors.New("boom")); got != 1 {
		t.Errorf("Code(generic) = %d, want 1", got)
	}
}

func TestCodeCatalog(t *testing.T) {
	if got := Code(ErrCatalog); got != 21 {
		t.Errorf("Code(ErrCatalog) = %d, want 21", got)
	}
	err := Catalog("rule %q broke", "x")
	if !errors.Is(err, ErrCatalog) {
		t.Error("Catalog() error should match ErrCatalog")
	}
	if got := Code(err); got != 21 {
		t.Errorf("Code(Catalog) = %d, want 21", got)
	}
	wrapped := fmt.Errorf("loading: %w", err)
	if got := Code(wrapped); got != 21 {
		t.Errorf("Code(wrapped Catalog) = %d, want 21", got)
	}
}

func TestCodeClusterSentinels(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"unreachable", ErrUnreachable, 3},
		{"unreachable wrapped", fmt.Errorf("connect: %w", ErrUnreachable), 3},
		{"auth", ErrAuth, 4},
		{"forbidden", ErrForbidden, 5},
		{"unknown product", ErrUnknownProduct, 10},
		{"findings", ErrFindings, 20},
		{"findings wrapped", fmt.Errorf("scan failed: %w", ErrFindings), 20},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Code(c.err); got != c.want {
				t.Errorf("Code(%v) = %d, want %d", c.err, got, c.want)
			}
		})
	}
}

func TestSignalCode(t *testing.T) {
	cases := []struct {
		sig  os.Signal
		want int
	}{
		{syscall.SIGINT, 130},
		{syscall.SIGTERM, 143},
		{syscall.SIGHUP, 1},
	}
	for _, c := range cases {
		if got := SignalCode(c.sig); got != c.want {
			t.Errorf("SignalCode(%v) = %d, want %d", c.sig, got, c.want)
		}
	}
}

func TestSilentNil(t *testing.T) {
	if got := Silent(nil); got != nil {
		t.Errorf("Silent(nil) = %v, want nil", got)
	}
	if IsSilent(nil) {
		t.Error("IsSilent(nil) = true, want false")
	}
}

func TestSilentPreservesChain(t *testing.T) {
	inner := Usage("--bad-flag")
	wrapped := Silent(inner)

	if !IsSilent(wrapped) {
		t.Error("IsSilent(Silent(...)) = false")
	}
	if !errors.Is(wrapped, ErrUsage) {
		t.Error("errors.Is should walk through Silent to ErrUsage")
	}
	if got := Code(wrapped); got != 2 {
		t.Errorf("Code(silent usage) = %d, want 2", got)
	}
	if wrapped.Error() != inner.Error() {
		t.Errorf("Silent should not change Error() text: got %q, want %q", wrapped.Error(), inner.Error())
	}
}

func TestIsSilentOnPlainErr(t *testing.T) {
	if IsSilent(errors.New("boom")) {
		t.Error("IsSilent(plain) = true, want false")
	}
}
