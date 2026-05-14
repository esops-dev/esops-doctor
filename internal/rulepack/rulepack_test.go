package rulepack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateAndVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "rule-a.yaml"), "id: a\n")
	mustWrite(t, filepath.Join(dir, "compliance", "rule-b.yaml"), "id: b\n")

	m, covered, err := Create(dir, "pack-name", "desc")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(covered) != 2 {
		t.Fatalf("expected 2 covered files, got %d (%v)", len(covered), covered)
	}
	if err := WriteManifest(dir, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	v, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.Name != "pack-name" {
		t.Errorf("Name = %q, want pack-name", v.Name)
	}
	if v.Version != ManifestVersion {
		t.Errorf("Version = %d, want %d", v.Version, ManifestVersion)
	}
}

func TestVerifyRejectsMissingManifest(t *testing.T) {
	dir := t.TempDir()
	_, err := Verify(dir)
	if err == nil {
		t.Fatal("expected error for missing manifest")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("error should mention missing manifest; got %v", err)
	}
}

func TestVerifyRejectsHashMismatch(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yaml")
	mustWrite(t, rulePath, "id: original\n")
	m, _, err := Create(dir, "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := WriteManifest(dir, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	// Mutate after the manifest is written.
	mustWrite(t, rulePath, "id: tampered\n")
	_, err = Verify(dir)
	if err == nil {
		t.Fatal("expected hash-mismatch error")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Errorf("error should mention hash mismatch; got %v", err)
	}
}

func TestVerifyRejectsUnlistedYAML(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "rule.yaml"), "id: a\n")
	m, _, err := Create(dir, "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := WriteManifest(dir, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	// Smuggle an unlisted YAML in after manifest creation. This is the
	// exact threat the manifest is supposed to mitigate.
	mustWrite(t, filepath.Join(dir, "smuggled.yaml"), "id: smuggled\n")
	_, err = Verify(dir)
	if err == nil {
		t.Fatal("expected unlisted-yaml error")
	}
	if !strings.Contains(err.Error(), "unlisted") {
		t.Errorf("error should mention unlisted yaml; got %v", err)
	}
}

func TestVerifyIgnoresNonYAMLSideCars(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "rule.yaml"), "id: a\n")
	m, _, err := Create(dir, "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := WriteManifest(dir, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	// Cosign sig + cert side-cars sit alongside MANIFEST.yaml. The
	// pack should accept them silently.
	mustWrite(t, filepath.Join(dir, "MANIFEST.yaml.sig"), "fake-signature")
	mustWrite(t, filepath.Join(dir, "MANIFEST.yaml.pem"), "fake-cert")
	mustWrite(t, filepath.Join(dir, "README.md"), "documentation")
	if _, err := Verify(dir); err != nil {
		t.Fatalf("Verify rejected non-YAML side cars: %v", err)
	}
}

func TestVerifyRejectsVersionMismatch(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "rule.yaml"), "id: a\n")
	m, _, err := Create(dir, "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	m.Version = 99
	if err := WriteManifest(dir, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	_, err = Verify(dir)
	if err == nil {
		t.Fatal("expected version-mismatch error")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("error should mention version; got %v", err)
	}
}

func TestVerifyRejectsAlgorithmMismatch(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "rule.yaml"), "id: a\n")
	m, _, err := Create(dir, "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	m.Algorithm = "md5"
	if err := WriteManifest(dir, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	_, err = Verify(dir)
	if err == nil {
		t.Fatal("expected algorithm-mismatch error")
	}
	if !strings.Contains(err.Error(), "algorithm") {
		t.Errorf("error should mention algorithm; got %v", err)
	}
}

func TestCreateRejectsEmptyPack(t *testing.T) {
	dir := t.TempDir()
	_, _, err := Create(dir, "", "")
	if err == nil {
		t.Fatal("expected error for empty pack")
	}
}

func TestSanitisePathRejectsAbsolute(t *testing.T) {
	if _, err := sanitisePath("/etc/passwd"); err == nil {
		t.Error("expected error for absolute path")
	}
}

func TestSanitisePathRejectsParent(t *testing.T) {
	if _, err := sanitisePath("../outside.yaml"); err == nil {
		t.Error("expected error for parent reference")
	}
}

func mustWrite(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
