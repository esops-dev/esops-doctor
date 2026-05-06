package waivers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/findings"
)

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func failResult(id string, sev findings.Severity, msg string) engine.RuleResult {
	return engine.RuleResult{
		RuleID: id,
		Status: engine.RuleStatusFail,
		Finding: &findings.Finding{
			RuleID:   id,
			Severity: sev,
			Message:  msg,
		},
	}
}

func TestLoadValidWaiverFile(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, ".esops-doctor.yaml", `
waivers:
  - rule_id: heap_size
    justification: SRE-approved exception
    expires_at: 2026-12-31
  - rule_id: tls_transport
    justification: Internal network only
`)
	set, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if set.Empty() {
		t.Fatal("expected non-empty set")
	}
	if set.Source() != p {
		t.Errorf("source = %q, want %q", set.Source(), p)
	}
}

func TestLoadRejectsMissingJustification(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "w.yaml", `
waivers:
  - rule_id: heap_size
`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error for missing justification")
	}
	if !strings.Contains(err.Error(), "justification is required") {
		t.Errorf("err should explain missing justification; got %v", err)
	}
}

func TestLoadRejectsBadExpiresAtFormat(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "w.yaml", `
waivers:
  - rule_id: heap_size
    justification: x
    expires_at: 2026/12/31
`)
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "expires_at") {
		t.Errorf("expected expires_at format error; got %v", err)
	}
}

func TestLoadRejectsDuplicateRuleID(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "w.yaml", `
waivers:
  - rule_id: heap_size
    justification: a
  - rule_id: heap_size
    justification: b
`)
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("expected duplicate-waiver error; got %v", err)
	}
}

func TestApplyAttachesActiveSuppression(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "w.yaml", `
waivers:
  - rule_id: heap_size
    justification: Approved by SRE
    expires_at: 2099-01-01
`)
	set, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	results := []engine.RuleResult{
		failResult("heap_size", findings.SeverityCritical, "Heap misconfigured"),
	}
	set.Apply(time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC), results)

	sup := results[0].Finding.Suppression
	if sup == nil {
		t.Fatal("expected suppression to be attached")
	}
	if sup.Expired {
		t.Error("waiver dated 2099 should not be expired in 2026")
	}
	if sup.Justification != "Approved by SRE" {
		t.Errorf("justification = %q", sup.Justification)
	}
	if !strings.Contains(results[0].Finding.Message, "Heap misconfigured") {
		t.Errorf("message should be unchanged for active waiver; got %q",
			results[0].Finding.Message)
	}
	if strings.Contains(results[0].Finding.Message, "expired") {
		t.Errorf("active waiver should not prefix with 'expired'; got %q",
			results[0].Finding.Message)
	}
}

func TestApplyExpiredFiresLoudWithPrefix(t *testing.T) {
	// Expired waivers fail loud — the finding re-surfaces with a
	// "waiver expired" prefix so they cannot rot silently.
	dir := t.TempDir()
	p := writeFile(t, dir, "w.yaml", `
waivers:
  - rule_id: heap_size
    justification: Was approved but lapsed
    expires_at: 2024-01-01
`)
	set, _ := Load(p)
	results := []engine.RuleResult{
		failResult("heap_size", findings.SeverityCritical, "Heap misconfigured"),
	}
	set.Apply(time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC), results)

	sup := results[0].Finding.Suppression
	if sup == nil || !sup.Expired {
		t.Fatalf("expected expired suppression; got %+v", sup)
	}
	if !strings.HasPrefix(results[0].Finding.Message, "[waiver expired 2024-01-01]") {
		t.Errorf("message should be prefixed with expired-waiver tag; got %q",
			results[0].Finding.Message)
	}
}

func TestApplySkipsNonFailureResults(t *testing.T) {
	set, _ := Load(writeFile(t, t.TempDir(), "w.yaml", `
waivers:
  - rule_id: heap_size
    justification: x
`))
	results := []engine.RuleResult{
		{RuleID: "heap_size", Status: engine.RuleStatusPass},
		{RuleID: "heap_size", Status: engine.RuleStatusSkipped},
	}
	set.Apply(time.Now(), results)
	for _, r := range results {
		if r.Finding != nil {
			t.Errorf("non-fail result should not have suppression attached; got %+v", r.Finding)
		}
	}
}

func TestLoadDefaultReturnsNilWhenNothingFound(t *testing.T) {
	dir := t.TempDir()
	wd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg"))
	t.Setenv("HOME", filepath.Join(dir, "home"))

	set, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	if set != nil {
		t.Errorf("expected nil set, got %+v", set)
	}
}

func TestLoadDefaultFindsCwdFile(t *testing.T) {
	dir := t.TempDir()
	wd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	writeFile(t, dir, DefaultFileName, `
waivers:
  - rule_id: heap_size
    justification: x
`)
	set, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	if set == nil || set.Empty() {
		t.Fatal("expected non-empty default-loaded set")
	}
}

func TestResolveAliasesRewritesSetKeys(t *testing.T) {
	dir := t.TempDir()
	// Operator wrote a waiver against the old rule name; the rule has
	// since been renamed and the old name lives on as a deprecated
	// alias. ResolveAliases should rewrite the set so the matching
	// rule_id at scan time still hits the waiver.
	p := writeFile(t, dir, "w.yaml", `
waivers:
  - rule_id: ilm_present
    justification: legacy entry
`)
	set, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	var resolved []string
	n := set.ResolveAliases(map[string]string{
		"ilm_present": "ilm_policy",
	}, func(alias, canonical string) {
		resolved = append(resolved, alias+"->"+canonical)
	})
	if n != 1 {
		t.Errorf("expected 1 rewrite, got %d", n)
	}
	if len(resolved) != 1 || resolved[0] != "ilm_present->ilm_policy" {
		t.Errorf("resolved callback wrong: %v", resolved)
	}

	// The waiver should now match the canonical id.
	results := []engine.RuleResult{
		failResult("ilm_policy", findings.SeverityError, "missing ILM"),
	}
	set.Apply(time.Now(), results)
	if results[0].Finding.Suppression == nil {
		t.Errorf("waiver should match the canonical id after alias resolution")
	}
}

func TestResolveAliasesPrefersExplicitCanonical(t *testing.T) {
	// If both the alias and the canonical id have explicit waivers,
	// the canonical wins — the operator named it explicitly, so the
	// alias-rewrite should not silently overwrite it.
	dir := t.TempDir()
	p := writeFile(t, dir, "w.yaml", `
waivers:
  - rule_id: ilm_present
    justification: alias entry
  - rule_id: ilm_policy
    justification: explicit canonical
`)
	set, _ := Load(p)
	set.ResolveAliases(map[string]string{"ilm_present": "ilm_policy"}, nil)

	results := []engine.RuleResult{
		failResult("ilm_policy", findings.SeverityError, "missing ILM"),
	}
	set.Apply(time.Now(), results)
	if got := results[0].Finding.Suppression.Justification; got != "explicit canonical" {
		t.Errorf("explicit canonical waiver should win; got %q", got)
	}
}

func TestResolveAliasesNoOpOnEmptyOrNilInputs(t *testing.T) {
	set, _ := Load(writeFile(t, t.TempDir(), "w.yaml", `
waivers:
  - rule_id: heap_size
    justification: x
`))
	if n := set.ResolveAliases(nil, nil); n != 0 {
		t.Errorf("nil aliases should be a no-op; got %d", n)
	}
	if n := set.ResolveAliases(map[string]string{}, nil); n != 0 {
		t.Errorf("empty aliases should be a no-op; got %d", n)
	}
}

func TestAppliedCountReflectsAttachedSuppressions(t *testing.T) {
	results := []engine.RuleResult{
		failResult("a", findings.SeverityWarn, "m"),
		failResult("b", findings.SeverityWarn, "m"),
	}
	results[0].Finding.Suppression = &findings.Suppression{Justification: "x"}
	if got := AppliedCount(results); got != 1 {
		t.Errorf("AppliedCount = %d, want 1", got)
	}
}
