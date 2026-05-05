package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

func TestValidateRulesEmbeddedHappyPath(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := runValidateRules(&out, &errOut, ""); err != nil {
		t.Fatalf("runValidateRules: %v", err)
	}
	if !strings.HasPrefix(out.String(), "OK:") {
		t.Errorf("stdout = %q, want OK prefix", out.String())
	}
	if errOut.Len() != 0 {
		t.Errorf("stderr should be empty on success; got %q", errOut.String())
	}
}

func TestValidateRulesAcceptsValidExtraDir(t *testing.T) {
	dir := t.TempDir()
	good := []byte(`checks:
  - id: extra_rule
    name: Extra
    category: extras
    severity: info
    description: Extra rule from --rules-dir
    probe: nodes
    condition: "true"
    message: m
    dialects: [elasticsearch, opensearch]
`)
	if err := os.WriteFile(filepath.Join(dir, "extra.yaml"), good, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if err := runValidateRules(&out, &errOut, dir); err != nil {
		t.Fatalf("runValidateRules: %v", err)
	}
	if !strings.Contains(out.String(), "OK:") {
		t.Errorf("stdout = %q, want OK prefix", out.String())
	}
}

func TestValidateRulesRejectsBadExtraDir(t *testing.T) {
	dir := t.TempDir()
	bad := []byte(`checks:
  - id: BadID
    name: ""
    category: x
    severity: info
    description: d
    probe: nodes
    condition: "true"
    message: m
    dialects: [elasticsearch]
`)
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	err := runValidateRules(&out, &errOut, dir)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !errors.Is(err, exit.ErrCatalog) {
		t.Errorf("err should match ErrCatalog (exit 21); got %v", err)
	}
	stderr := errOut.String()
	if !strings.Contains(stderr, "BadID") {
		t.Errorf("stderr should mention bad rule id; got %q", stderr)
	}
	if !strings.Contains(stderr, "issue(s)") {
		t.Errorf("stderr should include issue summary; got %q", stderr)
	}
}

func TestValidateRulesMissingDir(t *testing.T) {
	var out, errOut bytes.Buffer
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	err := runValidateRules(&out, &errOut, missing)
	if err == nil {
		t.Fatal("expected error for missing dir")
	}
	if !errors.Is(err, exit.ErrCatalog) {
		t.Errorf("err should match ErrCatalog; got %v", err)
	}
}

func TestValidateRulesCommandWiredIntoRoot(t *testing.T) {
	// Asserts the command is registered, so a future cleanup that
	// removes it from root.go fails this test rather than silently
	// breaking `esops-doctor validate-rules`.
	root := newRoot()
	for _, c := range root.Commands {
		if c.Name == "validate-rules" {
			return
		}
	}
	t.Fatal("validate-rules command not registered on root")
}

func TestValidateRulesRejectsBadCEL(t *testing.T) {
	// Schema is valid, but CEL fails to parse. Asserts the
	// engine.Compile pass is wired in and that its errors arrive on
	// stderr alongside schema issues, with exit code 21.
	dir := t.TempDir()
	body := []byte(`checks:
  - id: bad_cel
    name: Bad CEL
    category: x
    severity: warn
    description: rule whose condition is not parseable
    probe: nodes
    condition: "this is ( bad"
    message: m
    dialects: [elasticsearch]
`)
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	err := runValidateRules(&out, &errOut, dir)
	if err == nil {
		t.Fatal("expected CEL compile error to surface")
	}
	if !errors.Is(err, exit.ErrCatalog) {
		t.Errorf("err should match ErrCatalog (exit 21); got %v", err)
	}
	if !strings.Contains(errOut.String(), "CEL:") {
		t.Errorf("stderr should label CEL issues; got %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "bad_cel") {
		t.Errorf("stderr should reference offending rule id; got %q", errOut.String())
	}
}

func TestValidateRulesSkipsCELOnSchemaErrors(t *testing.T) {
	// When schema is broken, CEL compile is skipped — the schema
	// error is the actionable one and CEL parse errors on a malformed
	// rule would just be noise.
	dir := t.TempDir()
	body := []byte(`checks:
  - id: missing_fields
    severity: warn
    probe: nodes
    condition: "this is ( bad"
    dialects: [elasticsearch]
`)
	if err := os.WriteFile(filepath.Join(dir, "x.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if err := runValidateRules(&out, &errOut, dir); err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(errOut.String(), "CEL:") {
		t.Errorf("CEL pass should be suppressed when schema errors exist; got %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "name is required") {
		t.Errorf("schema errors should still surface; got %q", errOut.String())
	}
}

func TestValidateRulesEndToEnd(t *testing.T) {
	// Drives the command through the urfave entry point, exercising
	// global flags + Before hook on the way to the action. Skipping
	// the assertion on stdout text — runValidateRules writes directly
	// to os.Stdout under this path; we just want to confirm it exits 0.
	if err := Run(context.Background(), []string{"esops-doctor", "validate-rules"}); err != nil {
		t.Errorf("Run(validate-rules): %v", err)
	}
}
