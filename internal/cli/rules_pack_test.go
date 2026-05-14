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
	"github.com/esops-dev/esops-doctor/internal/rulepack"
)

func TestRulesPackCreateAndVerify(t *testing.T) {
	dir := t.TempDir()
	body := []byte(`checks:
  - id: pack_rule_a
    name: Pack rule A
    category: extras
    severity: info
    description: Pack-shipped rule.
    probe: nodes
    condition: "true"
    message: m
    dialects: [elasticsearch, opensearch]
`)
	if err := os.WriteFile(filepath.Join(dir, "rule-a.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	root := newRoot()
	root.Writer = &out
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "rules-pack", "create", dir,
		"--name", "test-pack",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, rulepack.ManifestFileName)); err != nil {
		t.Fatalf("manifest not written: %v", err)
	}
	if !strings.Contains(out.String(), "wrote") {
		t.Errorf("create stdout should report wrote; got %q", out.String())
	}

	out.Reset()
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "rules-pack", "verify", dir,
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(out.String(), "OK:") {
		t.Errorf("verify should print OK; got %q", out.String())
	}
}

func TestRulesPackVerifyDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "rule.yaml")
	body := []byte(`checks:
  - id: pack_rule_b
    name: Pack rule B
    category: extras
    severity: info
    description: Pack-shipped rule.
    probe: nodes
    condition: "true"
    message: m
    dialects: [elasticsearch]
`)
	if err := os.WriteFile(rule, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), []string{
		"esops-doctor", "rules-pack", "create", dir,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := os.WriteFile(rule, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), []string{
		"esops-doctor", "rules-pack", "verify", dir,
	})
	if err == nil {
		t.Fatal("expected verify to fail after tampering")
	}
	if !errors.Is(err, exit.ErrCatalog) {
		t.Errorf("err should be ErrCatalog (exit 21); got %v", err)
	}
}

func TestScanRulesPackLoadsAfterVerify(t *testing.T) {
	// loadLayeredCatalogWithPack should accept a verified pack alongside
	// the embedded catalog. We don't run a real scan (no cluster), just
	// confirm the loader path returns a merged catalog containing both
	// the embedded core and the pack's extra rule.
	dir := t.TempDir()
	body := []byte(`checks:
  - id: pack_rule_c
    name: Pack rule C
    category: extras
    severity: info
    description: Pack-shipped rule.
    probe: nodes
    condition: "true"
    message: m
    dialects: [elasticsearch, opensearch]
`)
	if err := os.WriteFile(filepath.Join(dir, "rule.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), []string{
		"esops-doctor", "rules-pack", "create", dir,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	cat, err := loadLayeredCatalogWithPack("", dir)
	if err != nil {
		t.Fatalf("loadLayeredCatalogWithPack: %v", err)
	}
	var found bool
	for _, r := range cat.Rules {
		if r.ID == "pack_rule_c" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected pack_rule_c in layered catalog")
	}
}

func TestRulesPackVerifyRequiresArgument(t *testing.T) {
	err := Run(context.Background(), []string{
		"esops-doctor", "rules-pack", "verify",
	})
	if err == nil {
		t.Fatal("expected usage error")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("err should be ErrUsage; got %v", err)
	}
}

func TestRulesPackCommandWiredIntoRoot(t *testing.T) {
	root := newRoot()
	for _, c := range root.Commands {
		if c.Name == "rules-pack" {
			return
		}
	}
	t.Fatal("rules-pack command not wired into root")
}
