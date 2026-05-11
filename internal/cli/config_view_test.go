package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	esopsconfig "github.com/esops-dev/esops-go/pkg/config"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

const viewSampleConfig = `current-context: prod

defaults:
  output: yaml

contexts:
  dev:
    url: http://localhost:9200
    auth:
      type: basic
      username: dev
      password: literal-dev-pass
    protection: none
  prod:
    url: https://prod.example.com:9200
    auth:
      type: api_key
      api_key: ${env:PROD_API_KEY}
    tls:
      cacert: /etc/esops/ca.crt
    protection: prod
`

// runConfigViewCmd is a small driver that runs `config view` with the
// given extra arguments and returns parsed YAML. Centralises the
// "configure root + capture stdout" boilerplate so each test
// asserts on shape, not on plumbing.
func runConfigViewCmd(t *testing.T, configPath string, args ...string) viewDoc {
	t.Helper()
	full := append([]string{"esops-doctor", "--config", configPath, "config", "view"}, args...)
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), full); err != nil {
		t.Fatalf("config view %v: %v", args, err)
	}
	var doc viewDoc
	if err := yaml.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("parse view output: %v\n%s", err, stdout.String())
	}
	return doc
}

// TestViewRedactsLiteralSecrets is the load-bearing test for #4: a
// literal password in the config file must never appear in `config
// view` output. Anything other than the exact placeholder is a
// regression that potentially leaks credentials into logs, screen
// recordings, or copy/paste.
func TestViewRedactsLiteralSecrets(t *testing.T) {
	path := writeTestConfig(t, viewSampleConfig)
	doc := runConfigViewCmd(t, path, "--all")
	devCtx, ok := doc.Contexts["dev"]
	if !ok {
		t.Fatal("dev context missing from output")
	}
	if devCtx.Auth == nil {
		t.Fatal("dev.auth missing")
	}
	if devCtx.Auth.Password != redactionPlaceholder {
		t.Errorf("literal password not redacted: got %q, want %q",
			devCtx.Auth.Password, redactionPlaceholder)
	}
	// The username is not a secret — should pass through unchanged.
	if devCtx.Auth.Username != "dev" {
		t.Errorf("username unexpectedly altered: %q", devCtx.Auth.Username)
	}
	// Sanity: the literal string must not appear anywhere in the
	// rendered output. Catches regressions where a different code
	// path bypasses redactLiteral.
	var raw bytes.Buffer
	root := newRoot()
	root.Writer = &raw
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", path, "config", "view", "--all",
	}); err != nil {
		t.Fatalf("view: %v", err)
	}
	if strings.Contains(raw.String(), "literal-dev-pass") {
		t.Errorf("raw output contains literal secret:\n%s", raw.String())
	}
}

// TestViewPreservesIndirectionRefs documents the boundary of
// redaction: a ${env:X} pointer is *not* a secret, just a name. The
// operator needs to see the reference to know where the credential
// lives; replacing it with REDACTED would erase useful information.
func TestViewPreservesIndirectionRefs(t *testing.T) {
	path := writeTestConfig(t, viewSampleConfig)
	doc := runConfigViewCmd(t, path)
	prodCtx, ok := doc.Contexts["prod"]
	if !ok {
		t.Fatal("prod context missing")
	}
	if prodCtx.Auth == nil {
		t.Fatal("prod.auth missing")
	}
	if prodCtx.Auth.APIKey != "${env:PROD_API_KEY}" {
		t.Errorf("ref not preserved: got %q, want %q",
			prodCtx.Auth.APIKey, "${env:PROD_API_KEY}")
	}
}

// TestViewDefaultsToCurrentContext confirms the un-flagged invocation
// renders only the current-context block (here: prod), not the full
// file. --all is the way to dump everything.
func TestViewDefaultsToCurrentContext(t *testing.T) {
	path := writeTestConfig(t, viewSampleConfig)
	doc := runConfigViewCmd(t, path)
	if _, ok := doc.Contexts["dev"]; ok {
		t.Error("dev context present without --all")
	}
	if _, ok := doc.Contexts["prod"]; !ok {
		t.Error("prod context missing — current-context not selected")
	}
}

// TestViewHonorsDefaultsOutput asserts the audit fix: defaults.output:
// json in the config file should make `config view` emit json without
// an explicit --output flag. Falls back to yaml when defaults.output
// is something view can't render (table/sarif/etc).
func TestViewHonorsDefaultsOutput(t *testing.T) {
	t.Run("defaults.output=json", func(t *testing.T) {
		path := writeTestConfig(t, strings.Replace(
			viewSampleConfig, "output: yaml", "output: json", 1))
		var stdout bytes.Buffer
		root := newRoot()
		root.Writer = &stdout
		if err := root.Run(context.Background(), []string{
			"esops-doctor", "--config", path, "config", "view",
		}); err != nil {
			t.Fatalf("view: %v", err)
		}
		// JSON starts with `{` after any leading whitespace.
		trimmed := strings.TrimSpace(stdout.String())
		if !strings.HasPrefix(trimmed, "{") {
			t.Errorf("not JSON output:\n%s", stdout.String())
		}
	})
	t.Run("defaults.output=table_falls_back_to_yaml", func(t *testing.T) {
		// `view` cannot render `table`; instead of erroring, it
		// falls back to yaml so an operator who configured
		// defaults.output for scan reports is not blocked from
		// viewing their config.
		path := writeTestConfig(t, strings.Replace(
			viewSampleConfig, "output: yaml", "output: table", 1))
		var stdout bytes.Buffer
		root := newRoot()
		root.Writer = &stdout
		if err := root.Run(context.Background(), []string{
			"esops-doctor", "--config", path, "config", "view",
		}); err != nil {
			t.Fatalf("view: %v", err)
		}
		var doc viewDoc
		if err := yaml.Unmarshal(stdout.Bytes(), &doc); err != nil {
			t.Errorf("expected yaml fallback but parse failed: %v\n%s", err, stdout.String())
		}
	})
}

func TestViewRejectsUnsupportedExplicitFormat(t *testing.T) {
	path := writeTestConfig(t, viewSampleConfig)
	for _, format := range []string{"table", "sarif", "junit", "html"} {
		t.Run(format, func(t *testing.T) {
			err := newRoot().Run(context.Background(), []string{
				"esops-doctor", "--config", path, "--output", format, "config", "view",
			})
			if err == nil {
				t.Fatalf("expected error for --output %s", format)
			}
			if !errors.Is(err, exit.ErrUsage) {
				t.Errorf("err is not ErrUsage: %v", err)
			}
		})
	}
}

func TestViewSelectedContextNotFoundIsUsageError(t *testing.T) {
	path := writeTestConfig(t, viewSampleConfig)
	err := newRoot().Run(context.Background(), []string{
		"esops-doctor", "--config", path, "--context", "bogus", "config", "view",
	})
	if err == nil {
		t.Fatal("expected usage error")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("err is not ErrUsage: %v", err)
	}
}

// TestRedactLiteralBehavior is the unit-level lock on the redaction
// helper. Worth a dedicated test because the rule (literal → REDACTED,
// empty → empty, ref → ref) is the only thing standing between an
// operator's password and stdout.
func TestRedactLiteralBehavior(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"hunter2", redactionPlaceholder},
		{"${env:FOO}", "${env:FOO}"},
		{"${file:/etc/secret}", "${file:/etc/secret}"},
		{"${keyring:svc/acct}", "${keyring:svc/acct}"},
		// Malformed-looking refs (not matching the strict pattern)
		// are treated as literals and redacted — fail safe.
		{"not-a-ref-${env:FOO", redactionPlaceholder},
		{"${ENV:FOO}", redactionPlaceholder}, // uppercase scheme — pattern requires lowercase
	}
	for _, c := range cases {
		if got := redactLiteral(c.in); got != c.want {
			t.Errorf("redactLiteral(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestProjectAuthRedactsAllSecretFields walks every secret-bearing
// field in viewAuth to make sure redactLiteral is wired for each.
// A future field added to Auth that bypasses redaction would not be
// caught by the higher-level integration tests above unless it
// happens to land in this fixture.
func TestProjectAuthRedactsAllSecretFields(t *testing.T) {
	auth := esopsconfig.Auth{
		Type:       "mixed",
		Username:   "ops",
		Password:   "literal-pw",
		APIKey:     "literal-ak",
		Token:      "literal-tok",
		ClientCert: "/etc/cert.pem",
		ClientKey:  "/etc/key.pem",
		Region:     "us-east-1",
		Service:    "es",
	}
	got := projectAuth(auth)
	if got == nil {
		t.Fatal("projectAuth returned nil for non-empty Auth")
	}
	for name, val := range map[string]string{
		"Password": got.Password,
		"APIKey":   got.APIKey,
		"Token":    got.Token,
	} {
		if val != redactionPlaceholder {
			t.Errorf("%s not redacted: got %q", name, val)
		}
	}
	// Non-secret fields must pass through.
	for name, val := range map[string]string{
		"Username":   got.Username,
		"ClientCert": got.ClientCert,
		"ClientKey":  got.ClientKey,
		"Region":     got.Region,
		"Service":    got.Service,
	} {
		if val == "" || val == redactionPlaceholder {
			t.Errorf("%s unexpectedly redacted or empty: %q", name, val)
		}
	}
}
