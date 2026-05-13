package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const configShowYAML = `
current-context: alpha
defaults:
  log_level: warn
contexts:
  alpha:
    url: http://example.test:9200
    auth:
      type: basic
      username: ops
      password: secret-literal-do-not-print
    protection: none
  beta:
    url: https://other.test:9200
    protection: prod
`

const configShowYAMLWithJSON = `
current-context: alpha
defaults:
  output: json
  log_level: warn
contexts:
  alpha:
    url: http://example.test:9200
    auth:
      type: basic
      username: ops
      password: secret-literal-do-not-print
    protection: none
  beta:
    url: https://other.test:9200
    protection: prod
`

func writeShowConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestConfigShowTextHighlightsSelectedContext confirms the human
// renderer prints the config path, current context (and its source),
// effective defaults, and the context list with a current marker.
func TestConfigShowTextHighlightsSelectedContext(t *testing.T) {
	path := writeShowConfig(t, configShowYAML)

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", path, "config", "show",
	}); err != nil {
		t.Fatalf("config show: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"Resolved configuration",
		"config_file:",
		path,
		"current_context: alpha",
		"source: current-context in",
		"selected:        alpha -> http://example.test:9200",
		"Defaults:",
		"log_level   warn",
		"log_level   warn",
		"Contexts (2):",
		"alpha",
		"http://example.test:9200",
		"beta",
		"prod",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("config show output missing %q\nfull output:\n%s", want, out)
		}
	}
	if strings.Contains(out, "secret-literal-do-not-print") {
		t.Error("config show must not leak the inline password literal")
	}
}

// TestConfigShowContextFlagOverridesCurrent confirms --context flag
// switches the selected context source and marks the right row as
// current.
func TestConfigShowContextFlagOverridesCurrent(t *testing.T) {
	path := writeShowConfig(t, configShowYAML)

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", path, "--context", "beta", "config", "show",
	}); err != nil {
		t.Fatalf("config show: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "source: --context flag") {
		t.Errorf("expected context source attribution; got %q", out)
	}
	if !strings.Contains(out, "selected:        beta -> https://other.test:9200") {
		t.Errorf("expected beta selected; got %q", out)
	}
}

// TestConfigShowSurfacesResolutionError confirms a context whose
// secret indirection cannot be resolved (e.g. ${env:NOT_SET})
// surfaces the failure inline rather than silently dropping the
// selected_context block.
func TestConfigShowSurfacesResolutionError(t *testing.T) {
	const envKey = "DEFINITELY_NOT_SET_TEST_VAR_XYZ"
	body := `
current-context: alpha
contexts:
  alpha:
    url: http://example.test:9200
    auth:
      type: basic
      username: ops
      password: ${env:` + envKey + `}
    protection: none
`
	path := writeShowConfig(t, body)
	// The upstream config resolver uses os.LookupEnv to distinguish
	// "set to empty" from "not set". Force the "not set" branch by
	// unsetting the var for the duration of the test.
	if prev, ok := os.LookupEnv(envKey); ok {
		t.Cleanup(func() { _ = os.Setenv(envKey, prev) })
	} else {
		t.Cleanup(func() { _ = os.Unsetenv(envKey) })
	}
	if err := os.Unsetenv(envKey); err != nil {
		t.Fatalf("unset env: %v", err)
	}

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", path, "config", "show",
	}); err != nil {
		t.Fatalf("config show: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "resolution_error:") {
		t.Errorf("expected resolution_error section; got %q", out)
	}
}

// TestConfigShowJSONRoundtrip confirms --output json emits a
// schema-friendly document carrying the resolved fields.
func TestConfigShowJSONRoundtrip(t *testing.T) {
	path := writeShowConfig(t, configShowYAMLWithJSON)

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", path, "--output", "json", "config", "show",
	}); err != nil {
		t.Fatalf("config show: %v", err)
	}

	var doc struct {
		ConfigFile     string `json:"config_file"`
		CurrentContext string `json:"current_context"`
		Defaults       struct {
			Output string `json:"output"`
		} `json:"defaults"`
		Contexts []struct {
			Name    string `json:"name"`
			URL     string `json:"url"`
			Current bool   `json:"current"`
		} `json:"contexts"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("not valid json: %v\n%s", err, stdout.String())
	}
	if doc.CurrentContext != "alpha" {
		t.Errorf("current_context = %q, want alpha", doc.CurrentContext)
	}
	if doc.Defaults.Output != "json" {
		t.Errorf("defaults.output = %q, want json", doc.Defaults.Output)
	}
	if len(doc.Contexts) != 2 {
		t.Fatalf("contexts = %d, want 2", len(doc.Contexts))
	}
	var foundCurrent bool
	for _, c := range doc.Contexts {
		if c.Current && c.Name != "alpha" {
			t.Errorf("current context flag on wrong row: %+v", c)
		}
		if c.Current {
			foundCurrent = true
		}
	}
	if !foundCurrent {
		t.Errorf("expected one current=true row; got %+v", doc.Contexts)
	}
}
