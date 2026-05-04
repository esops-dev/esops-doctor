package config

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleConfig = `current-context: prod
defaults:
  log_level: warn
  log_format: json
  output: table
  timeout: 30s
contexts:
  prod:
    url: https://es.prod.example.com:9200
    timeout: 10s
  staging:
    urls:
      - https://es-1.staging.example.com:9200
      - https://es-2.staging.example.com:9200
`

func writeConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(sampleConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParse(t *testing.T) {
	path := writeConfig(t)
	cfg, err := Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CurrentContext != "prod" {
		t.Errorf("CurrentContext = %q, want prod", cfg.CurrentContext)
	}
	if cfg.Defaults.LogLevel != "warn" {
		t.Errorf("Defaults.LogLevel = %q, want warn", cfg.Defaults.LogLevel)
	}
	if cfg.Defaults.LogFormat != "json" {
		t.Errorf("Defaults.LogFormat = %q, want json", cfg.Defaults.LogFormat)
	}
	if got := cfg.Contexts["prod"].URL; got != "https://es.prod.example.com:9200" {
		t.Errorf("prod.URL = %q", got)
	}
	if got := cfg.Contexts["staging"].Addresses(); len(got) != 2 {
		t.Errorf("staging.Addresses len = %d, want 2", len(got))
	}
}

func TestResolveExplicit(t *testing.T) {
	got, err := Resolve("/some/explicit/path")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/some/explicit/path" {
		t.Errorf("Resolve(explicit) = %q, want explicit path back", got)
	}
}

func TestResolveEnvMissing(t *testing.T) {
	t.Setenv("ESOPS_CONFIG", "/definitely/not/here.yaml")
	t.Setenv("XDG_CONFIG_HOME", "")
	if _, err := Resolve(""); err == nil {
		t.Error("Resolve with broken ESOPS_CONFIG: expected error")
	}
}

func TestResolveEnvSet(t *testing.T) {
	path := writeConfig(t)
	t.Setenv("ESOPS_CONFIG", path)
	got, err := Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Errorf("Resolve = %q, want %q", got, path)
	}
}

func TestResolveXDG(t *testing.T) {
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "esops")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfgDir, "config.yaml")
	if err := os.WriteFile(path, []byte(sampleConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ESOPS_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Chdir(t.TempDir()) // avoid picking up ./esops.yaml
	got, err := Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Errorf("Resolve = %q, want %q", got, path)
	}
}

func TestResolveContextExplicit(t *testing.T) {
	cfg, err := Parse(writeConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	name, ctx, err := cfg.ResolveContext("staging")
	if err != nil {
		t.Fatal(err)
	}
	if name != "staging" {
		t.Errorf("name = %q, want staging", name)
	}
	if len(ctx.Addresses()) != 2 {
		t.Errorf("Addresses len = %d, want 2", len(ctx.Addresses()))
	}
}

func TestResolveContextDefaultsToCurrent(t *testing.T) {
	cfg, err := Parse(writeConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	name, _, err := cfg.ResolveContext("")
	if err != nil {
		t.Fatal(err)
	}
	if name != "prod" {
		t.Errorf("name = %q, want prod (current-context)", name)
	}
}

func TestResolveContextUnknown(t *testing.T) {
	cfg, err := Parse(writeConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cfg.ResolveContext("missing"); err == nil {
		t.Error("ResolveContext with missing name: expected error")
	}
}

func TestResolveContextNoneSet(t *testing.T) {
	cfg := Config{Contexts: map[string]Context{"a": {URL: "x"}}}
	if _, _, err := cfg.ResolveContext(""); err == nil {
		t.Error("ResolveContext with no name and no current-context: expected error")
	}
}

func TestResolveContextInheritsTimeout(t *testing.T) {
	cfg, err := Parse(writeConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	_, ctx, err := cfg.ResolveContext("staging")
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Timeout != cfg.Defaults.Timeout {
		t.Errorf("staging Timeout = %v, want default %v", ctx.Timeout, cfg.Defaults.Timeout)
	}
}
