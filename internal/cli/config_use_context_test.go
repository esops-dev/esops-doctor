package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

const switchTargetConfig = `current-context: dev

contexts:
  dev:
    url: http://localhost:9200
    protection: none
  prod:
    url: https://prod.example.com:9200
    protection: prod
`

func TestUseContextSwitchesAndWritesFile(t *testing.T) {
	path := writeTestConfig(t, switchTargetConfig)
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", path, "config", "use-context", "prod",
	}); err != nil {
		t.Fatalf("use-context: %v", err)
	}
	if !strings.Contains(stdout.String(), "prod") {
		t.Errorf("stdout missing context name: %q", stdout.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(data), "current-context: prod") {
		t.Errorf("file not updated; got:\n%s", data)
	}
	// The contexts: block must still be present — SetCurrentContext
	// only rewrites the single line, but a regression here would
	// silently wipe the rest of the file.
	if !strings.Contains(string(data), "contexts:") {
		t.Errorf("contexts block missing after switch:\n%s", data)
	}
}

func TestUseContextNoOpOnSameContext(t *testing.T) {
	path := writeTestConfig(t, switchTargetConfig)
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", path, "config", "use-context", "dev",
	}); err != nil {
		t.Fatalf("use-context: %v", err)
	}
	if !strings.Contains(stdout.String(), "Already on context") {
		t.Errorf("expected no-op message, got: %q", stdout.String())
	}
}

func TestUseContextMissingArgIsUsageError(t *testing.T) {
	path := writeTestConfig(t, switchTargetConfig)
	root := newRoot()
	var stderr bytes.Buffer
	root.ErrWriter = &stderr
	err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", path, "config", "use-context",
	})
	if err == nil {
		t.Fatal("expected usage error")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("err is not ErrUsage: %v", err)
	}
}

func TestUseContextUnknownNameIsUsageError(t *testing.T) {
	path := writeTestConfig(t, switchTargetConfig)
	root := newRoot()
	err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", path, "config", "use-context", "bogus",
	})
	if err == nil {
		t.Fatal("expected error for unknown context")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("err is not ErrUsage: %v", err)
	}
	// Operator-facing message should list available names so the
	// next attempt is informed.
	for _, want := range []string{"bogus", "dev", "prod"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}
}
