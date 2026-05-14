package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

func TestValidateRulesEmbeddedHappyPath(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := runValidateRules(&out, &errOut, "", "", false, ""); err != nil {
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
	if err := runValidateRules(&out, &errOut, dir, "", false, ""); err != nil {
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
	err := runValidateRules(&out, &errOut, dir, "", false, "")
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
	err := runValidateRules(&out, &errOut, missing, "", false, "")
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
	err := runValidateRules(&out, &errOut, dir, "", false, "")
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
	if err := runValidateRules(&out, &errOut, dir, "", false, ""); err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(errOut.String(), "CEL:") {
		t.Errorf("CEL pass should be suppressed when schema errors exist; got %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "name is required") {
		t.Errorf("schema errors should still surface; got %q", errOut.String())
	}
}

func TestValidateRulesRejectsUnknownProbe(t *testing.T) {
	// Schema is valid; CEL is fine; but the probe name has no
	// registered adapter. Asserts ValidateProbes is wired in and
	// fires before CEL compile so an operator who renamed a probe
	// in YAML sees a clear "unknown probe" message rather than a
	// surprise scan-time skip.
	dir := t.TempDir()
	body := []byte(`checks:
  - id: bogus_probe
    name: Bogus
    category: x
    severity: warn
    description: rule whose probe is not registered
    probe: not_a_real_probe
    condition: "true"
    message: m
    dialects: [elasticsearch]
`)
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	err := runValidateRules(&out, &errOut, dir, "", false, "")
	if err == nil {
		t.Fatal("expected unknown-probe error to surface")
	}
	if !errors.Is(err, exit.ErrCatalog) {
		t.Errorf("err should match ErrCatalog (exit 21); got %v", err)
	}
	if !strings.Contains(errOut.String(), "unknown probe") {
		t.Errorf("stderr should mention unknown probe; got %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "not_a_real_probe") {
		t.Errorf("stderr should reference the bad probe name; got %q", errOut.String())
	}
}

func TestValidateRulesLayersUserRulesDir(t *testing.T) {
	// TestMain pins XDG_CONFIG_HOME to a tempdir. Drop a rule there and
	// confirm validate-rules counts it in the OK summary — proves the
	// user-overrides path is layered alongside --rules-dir, matching
	// scan / list-rules / explain. Asymmetric behaviour would silently
	// skip an operator's user-dir rule until they ran scan against a
	// real cluster.
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		t.Skip("XDG_CONFIG_HOME not set in test env")
	}
	rulesDir := filepath.Join(xdg, "esops-doctor", "rules.d")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(xdg, "esops-doctor")) })

	// Baseline run before the user rule lands so we can assert the
	// count grew by exactly one rather than hard-coding a number that
	// rots every time the embedded catalog grows.
	var baseOut, baseErr bytes.Buffer
	if err := runValidateRules(&baseOut, &baseErr, "", "", false, ""); err != nil {
		t.Fatalf("runValidateRules baseline: %v", err)
	}
	baseN := parseValidatedCount(t, baseOut.String())

	body := []byte(`checks:
  - id: validate_user_rule
    name: User Rule
    category: extras
    severity: info
    description: Lives in the user rules.d directory.
    probe: nodes
    condition: "true"
    message: m
    dialects: [elasticsearch]
`)
	if err := os.WriteFile(filepath.Join(rulesDir, "u.yaml"), body, 0o600); err != nil {
		t.Fatalf("write rule: %v", err)
	}

	var out, errOut bytes.Buffer
	if err := runValidateRules(&out, &errOut, "", "", false, ""); err != nil {
		t.Fatalf("runValidateRules: %v", err)
	}
	if !strings.Contains(out.String(), "OK:") {
		t.Errorf("expected OK summary; got stdout=%q stderr=%q", out.String(), errOut.String())
	}
	if got := parseValidatedCount(t, out.String()); got != baseN+1 {
		t.Errorf("validated count = %d, want %d (baseline %d + 1 user rule)", got, baseN+1, baseN)
	}
}

// parseValidatedCount extracts N from "OK: N rule(s) validated\n".
// Used to assert that user-dir rule layering increases the count by
// the expected delta without hard-coding the embedded catalog size.
func parseValidatedCount(t *testing.T, stdout string) int {
	t.Helper()
	const prefix = "OK: "
	const suffix = " rule(s)"
	i := strings.Index(stdout, prefix)
	j := strings.Index(stdout, suffix)
	if i < 0 || j < 0 || j <= i+len(prefix) {
		t.Fatalf("could not parse rule count from %q", stdout)
	}
	var n int
	if _, err := fmt.Sscanf(stdout[i+len(prefix):j], "%d", &n); err != nil {
		t.Fatalf("could not parse rule count from %q: %v", stdout, err)
	}
	return n
}

func TestValidateRulesSurfacesUserDirIssues(t *testing.T) {
	// Same scenario as TestValidateRulesLayersUserRulesDir, but the
	// user-dir rule is malformed. Asserts the per-issue stderr UX
	// reports the user-dir violation by source — operators iterating
	// in the user dir need addressable errors, not "rule catalog
	// invalid: <bundle>".
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		t.Skip("XDG_CONFIG_HOME not set in test env")
	}
	rulesDir := filepath.Join(xdg, "esops-doctor", "rules.d")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(xdg, "esops-doctor")) })
	body := []byte(`checks:
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
	if err := os.WriteFile(filepath.Join(rulesDir, "bad.yaml"), body, 0o600); err != nil {
		t.Fatalf("write rule: %v", err)
	}

	var out, errOut bytes.Buffer
	err := runValidateRules(&out, &errOut, "", "", false, "")
	if err == nil {
		t.Fatal("expected validation error from malformed user-dir rule")
	}
	if !errors.Is(err, exit.ErrCatalog) {
		t.Errorf("err should match ErrCatalog (exit 21); got %v", err)
	}
	if !strings.Contains(errOut.String(), "BadID") {
		t.Errorf("stderr should reference offending rule id; got %q", errOut.String())
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

func TestValidateRulesStrictPassesAgainstRepoFixtures(t *testing.T) {
	// Running --strict against the repo's own testdata tree should
	// succeed — that's the same gate TestEveryRuleHasFixtures enforces.
	fixtures := filepath.Join("..", "..", "testdata", "rule_fixtures")
	var out, errOut bytes.Buffer
	if err := runValidateRules(&out, &errOut, "", "", true, fixtures); err != nil {
		t.Fatalf("runValidateRules --strict: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.HasPrefix(out.String(), "OK:") {
		t.Errorf("expected OK; got stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

func TestValidateRulesStrictRejectsMissingFixtures(t *testing.T) {
	// Point --strict at a directory that has no fixtures for the
	// embedded rules. Every embedded rule should surface as a
	// missing-fixture issue; without --strict the catalog itself
	// remains valid.
	emptyDir := t.TempDir()
	var out, errOut bytes.Buffer
	err := runValidateRules(&out, &errOut, "", "", true, emptyDir)
	if err == nil {
		t.Fatal("expected --strict to fail without fixtures")
	}
	if !errors.Is(err, exit.ErrCatalog) {
		t.Errorf("err should be ErrCatalog; got %v", err)
	}
	if !strings.Contains(errOut.String(), "missing fixture") {
		t.Errorf("stderr should mention missing fixture; got %q", errOut.String())
	}
}

func TestValidateRulesStrictSkipsRulesDirRules(t *testing.T) {
	// --rules-dir rules are NOT in the doctor repo's testdata tree, so
	// --strict skips them (the catalog-hygiene gate covers the embedded
	// catalog only — operator packs ship their own fixtures, if any).
	rulesDir := t.TempDir()
	body := []byte(`checks:
  - id: extras_pack_rule
    name: Extras pack rule
    category: extras
    severity: info
    description: Layered rule with no fixture in the repo testdata tree.
    probe: nodes
    condition: "true"
    message: m
    dialects: [elasticsearch, opensearch]
`)
	if err := os.WriteFile(filepath.Join(rulesDir, "extras.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	repoFixtures := filepath.Join("..", "..", "testdata", "rule_fixtures")
	if err := runValidateRules(&out, &errOut, rulesDir, "", true, repoFixtures); err != nil {
		t.Fatalf("runValidateRules: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.HasPrefix(out.String(), "OK:") {
		t.Errorf("expected OK; got stdout=%q stderr=%q", out.String(), errOut.String())
	}
}
