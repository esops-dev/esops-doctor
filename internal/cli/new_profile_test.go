package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

// The skeleton-shape, --name, and rules-dir-override paths are
// already exercised by profile_file_test.go's TestNewProfile*
// suite. This file covers the one gap left over: whitespace-only
// --name should fail loud, not silently produce a profile with an
// empty `name:` field that a downstream loader would reject.
func TestNewProfileRejectsEmptyName(t *testing.T) {
	err := newRoot().Run(context.Background(), []string{
		"esops-doctor", "new-profile", "--name", "  ",
	})
	if err == nil {
		t.Fatal("expected usage error for whitespace-only --name")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("err is not ErrUsage: %v", err)
	}
}
