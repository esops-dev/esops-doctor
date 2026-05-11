package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

// writeTestConfig drops a config YAML in a temp dir with mode 0600
// (the loader rejects world-readable files in safety mode) and
// returns its path. Used by every config-subcommand test to avoid
// touching the operator's real $HOME or $XDG_CONFIG_HOME.
func writeTestConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

const sampleConfigYAML = `current-context: dev

contexts:
  dev:
    url: http://localhost:9200
    protection: none
  staging:
    url: https://staging.example.com:9200
    auth:
      type: basic
      username: ops
      password: hunter2
    protection: read-only
  prod:
    url: https://prod.example.com:9200
    auth:
      type: api_key
      api_key: ${env:PROD_API_KEY}
    tls:
      cacert: /etc/esops/ca.crt
    protection: prod
`

func TestGetContextsTable(t *testing.T) {
	path := writeTestConfig(t, sampleConfigYAML)
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", path, "config", "get-contexts",
	}); err != nil {
		t.Fatalf("get-contexts: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"CURRENT", "NAME", "URL", "AUTH", "PROTECTION",
		"dev", "staging", "prod",
		"http://localhost:9200",
		"none", "basic", "api_key", "read-only",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q\nfull output:\n%s", want, out)
		}
	}
	// Current marker should be on the dev row only.
	for _, line := range strings.Split(out, "\n") {
		hasStar := strings.HasPrefix(line, "*")
		hasDev := strings.Contains(line, "dev")
		if hasStar && !hasDev {
			t.Errorf("current marker on a non-dev row: %q", line)
		}
	}
}

func TestGetContextsJSON(t *testing.T) {
	path := writeTestConfig(t, sampleConfigYAML)
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", path, "--output", "json", "config", "get-contexts",
	}); err != nil {
		t.Fatalf("get-contexts json: %v", err)
	}
	var entries []contextEntry
	if err := json.Unmarshal(stdout.Bytes(), &entries); err != nil {
		t.Fatalf("not valid json: %v\n%s", err, stdout.String())
	}
	if len(entries) != 3 {
		t.Fatalf("want 3 entries, got %d", len(entries))
	}
	// Sorted alphabetically: dev, prod, staging.
	wantNames := []string{"dev", "prod", "staging"}
	for i, want := range wantNames {
		if entries[i].Name != want {
			t.Errorf("entries[%d].Name = %q, want %q", i, entries[i].Name, want)
		}
	}
	if !entries[0].Current {
		t.Error("dev entry not marked current")
	}
	if entries[1].Current || entries[2].Current {
		t.Error("non-dev entry marked current")
	}
}

func TestGetContextsYAML(t *testing.T) {
	path := writeTestConfig(t, sampleConfigYAML)
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", path, "--output", "yaml", "config", "get-contexts",
	}); err != nil {
		t.Fatalf("get-contexts yaml: %v", err)
	}
	var entries []contextEntry
	if err := yaml.Unmarshal(stdout.Bytes(), &entries); err != nil {
		t.Fatalf("not valid yaml: %v\n%s", err, stdout.String())
	}
	if len(entries) != 3 {
		t.Fatalf("want 3 entries, got %d", len(entries))
	}
}

func TestGetContextsRejectsScanOnlyFormat(t *testing.T) {
	path := writeTestConfig(t, sampleConfigYAML)
	for _, format := range []string{"sarif", "junit", "html"} {
		t.Run(format, func(t *testing.T) {
			var stdout bytes.Buffer
			root := newRoot()
			root.Writer = &stdout
			err := root.Run(context.Background(), []string{
				"esops-doctor", "--config", path, "--output", format, "config", "get-contexts",
			})
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, exit.ErrUsage) {
				t.Errorf("err is not ErrUsage: %v", err)
			}
		})
	}
}
