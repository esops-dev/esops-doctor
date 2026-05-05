package engine

import (
	"errors"
	"strings"
	"testing"

	"github.com/esops-dev/esops-doctor/internal/findings"
	"github.com/esops-dev/esops-doctor/internal/rules"
)

// validRule is the helper test fixture — enough fields populated for
// Compile to succeed when the condition is well-formed.
func validRule(id, condition string) rules.Rule {
	return rules.Rule{
		ID:          id,
		Name:        id,
		Category:    "test",
		Severity:    findings.SeverityWarn,
		Description: "test rule",
		Probe:       "nodes",
		Condition:   condition,
		Message:     "msg",
		Dialects:    []string{"elasticsearch", "opensearch"},
	}
}

func TestCompileSucceedsOnGoodRule(t *testing.T) {
	cat := &rules.Catalog{Rules: []rules.Rule{
		validRule("r1", "size(self) > 0"),
	}}
	eng, err := Compile(cat)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if got := eng.Rules(); len(got) != 1 {
		t.Errorf("Rules() = %d entries, want 1", len(got))
	}
}

func TestCompileFailsOnSyntaxError(t *testing.T) {
	cat := &rules.Catalog{Rules: []rules.Rule{
		validRule("r1", "this isn't ( CEL )"),
	}}
	_, err := Compile(cat)
	if err == nil {
		t.Fatal("expected compile error")
	}
	var ce *CompileError
	if !errors.As(err, &ce) || len(ce.Failures) == 0 {
		t.Fatalf("err should be *CompileError with at least one failure; got %v", err)
	}
	if ce.Failures[0].RuleID != "r1" {
		t.Errorf("failure should reference rule id; got %+v", ce.Failures[0])
	}
}

func TestCompileFailsOnNonBoolCondition(t *testing.T) {
	cat := &rules.Catalog{Rules: []rules.Rule{
		validRule("r1", "size(self)"), // returns int, not bool
	}}
	_, err := Compile(cat)
	if err == nil {
		t.Fatal("expected error for non-bool condition")
	}
	if !strings.Contains(err.Error(), "must return bool") {
		t.Errorf("error should mention bool requirement; got %v", err)
	}
}

func TestCompileCollectsAllFailures(t *testing.T) {
	cat := &rules.Catalog{Rules: []rules.Rule{
		validRule("r1", "this is ( bad"),
		validRule("r2", "more ) bad ("),
		validRule("r3", "size(self) > 0"), // good
	}}
	_, err := Compile(cat)
	if err == nil {
		t.Fatal("expected error")
	}
	var ce *CompileError
	if !errors.As(err, &ce) {
		t.Fatalf("err type: %T", err)
	}
	if len(ce.Failures) != 2 {
		t.Errorf("Failures = %d, want 2 (r1, r2)", len(ce.Failures))
	}
}

func TestCompileEmbedsSourceInError(t *testing.T) {
	r := validRule("r1", "this is bad")
	r.Source = "rules/cat-a/r1.yaml"
	_, err := Compile(&rules.Catalog{Rules: []rules.Rule{r}})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "rules/cat-a/r1.yaml") {
		t.Errorf("error should reference source path; got %v", err)
	}
}

func TestRuleStatusString(t *testing.T) {
	cases := map[RuleStatus]string{
		RuleStatusPass:    "pass",
		RuleStatusFail:    "fail",
		RuleStatusSkipped: "skipped",
		RuleStatusError:   "error",
		RuleStatus(99):    "unknown",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("RuleStatus(%d).String() = %q, want %q", s, got, want)
		}
	}
}

// TestEmbeddedCatalogCompiles is the engine equivalent of the rules
// package's "embedded catalog validates" test: the shipped CEL must
// parse, type-check, and accept a bool output. Failures here mean a
// rule shipped without working CEL.
func TestEmbeddedCatalogCompiles(t *testing.T) {
	cat, err := rules.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if _, err := Compile(cat); err != nil {
		t.Fatalf("embedded catalog failed CEL compile:\n%v", err)
	}
}
