package rules

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/esops-dev/esops-doctor/internal/findings"
)

// validRule is the in-memory equivalent of goodRule: a Rule that
// passes Validate. Tests construct it then mutate one field to assert
// each individual check fires.
func validRule() Rule {
	return Rule{
		ID:          "example_rule",
		Name:        "Example",
		Category:    "example",
		Severity:    findings.SeverityWarn,
		Description: "Example rule used in tests.",
		Probe:       "nodes",
		Condition:   "size(self) > 0",
		Message:     "example",
		Dialects:    []string{"elasticsearch", "opensearch"},
		Source:      "test.yaml",
	}
}

func TestValidationErrorString(t *testing.T) {
	cases := []struct {
		name string
		in   ValidationError
		want string
	}{
		{"with-id", ValidationError{Source: "x.yaml", RuleID: "foo", Message: "bad"}, `x.yaml: rule "foo": bad`},
		{"file-only", ValidationError{Source: "x.yaml", Message: "bad"}, "x.yaml: bad"},
		{"bare", ValidationError{Message: "bad"}, "bad"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.in.Error(); got != c.want {
				t.Errorf("Error() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestValidatePassesGoodRule(t *testing.T) {
	cat := &Catalog{Rules: []Rule{validRule()}}
	if errs := cat.Validate(); len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

// TestValidateFieldByField mutates a single field and asserts that an
// error mentioning the field appears. Cheaper than one test per case
// and the table reads as the requirement spec.
func TestValidateFieldByField(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*Rule)
		mustMatch string
	}{
		{"empty id", func(r *Rule) { r.ID = "" }, "id is required"},
		{"bad id charset", func(r *Rule) { r.ID = "Bad-ID" }, "id must match"},
		{"empty name", func(r *Rule) { r.Name = "" }, "name is required"},
		{"empty category", func(r *Rule) { r.Category = "" }, "category is required"},
		{"missing severity", func(r *Rule) { r.Severity = findings.SeverityUnknown }, "severity is required"},
		{"empty description", func(r *Rule) { r.Description = "" }, "description is required"},
		{"empty probe", func(r *Rule) { r.Probe = "" }, "probe is required"},
		{"empty condition", func(r *Rule) { r.Condition = "" }, "condition is required"},
		{"empty message", func(r *Rule) { r.Message = "" }, "message is required"},
		{"no dialects", func(r *Rule) { r.Dialects = nil }, "dialects must list at least one"},
		{"unknown dialect", func(r *Rule) { r.Dialects = []string{"solr"} }, `unknown dialect "solr"`},
		{"unknown effort", func(r *Rule) { r.Effort = "trivial" }, `unknown effort "trivial"`},
		{"alias bad charset", func(r *Rule) { r.DeprecatedAliases = []string{"Bad-Alias"} }, `deprecated_alias "Bad-Alias"`},
		{"alias empty", func(r *Rule) { r.DeprecatedAliases = []string{""} }, "deprecated_aliases entries must be non-empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := validRule()
			c.mutate(&r)
			cat := &Catalog{Rules: []Rule{r}}
			errs := cat.Validate()
			found := false
			for _, e := range errs {
				if strings.Contains(e.Message, c.mustMatch) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected an error containing %q, got %v", c.mustMatch, errs)
			}
		})
	}
}

func TestValidateAcceptsKnownEfforts(t *testing.T) {
	// Empty effort is allowed (optional field); low/medium/high are
	// the documented values. Anything else is rejected by
	// TestValidateFieldByField above.
	for _, eff := range []string{"", "low", "medium", "high"} {
		r := validRule()
		r.Effort = eff
		cat := &Catalog{Rules: []Rule{r}}
		if errs := cat.Validate(); len(errs) != 0 {
			t.Errorf("effort=%q: unexpected errors %v", eff, errs)
		}
	}
}

func TestValidateAcceptsValidDocURL(t *testing.T) {
	r := validRule()
	r.Remediation.DocURL = "https://example.com/docs"
	cat := &Catalog{Rules: []Rule{r}}
	if errs := cat.Validate(); len(errs) != 0 {
		t.Errorf("unexpected errors with valid doc_url: %v", errs)
	}
}

func TestValidateRejectsBadDocURL(t *testing.T) {
	// net/url is permissive enough that triggering Parse() failure
	// reliably is awkward; an invalid control byte in the URL does it.
	r := validRule()
	r.Remediation.DocURL = "https://example.com/\x7f"
	cat := &Catalog{Rules: []Rule{r}}
	errs := cat.Validate()
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "invalid remediation doc_url") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected doc_url error, got %v", errs)
	}
}

func TestValidateDuplicateIDs(t *testing.T) {
	r1 := validRule()
	r1.Source = "first.yaml"
	r2 := validRule()
	r2.Source = "second.yaml"
	cat := &Catalog{Rules: []Rule{r1, r2}}
	errs := cat.Validate()
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "duplicate id") && strings.Contains(e.Message, "first.yaml") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected duplicate-id error referencing first.yaml; got %v", errs)
	}
}

func TestValidateAliasCollidesWithID(t *testing.T) {
	r1 := validRule()
	r1.ID = "rule_a"
	r1.Source = "a.yaml"
	r2 := validRule()
	r2.ID = "rule_b"
	r2.Source = "b.yaml"
	r2.DeprecatedAliases = []string{"rule_a"} // collides with r1's id
	cat := &Catalog{Rules: []Rule{r1, r2}}
	errs := cat.Validate()
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "deprecated_alias") && strings.Contains(e.Message, "rule_a") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected alias-collision error, got %v", errs)
	}
}

func TestValidateProbesAcceptsKnown(t *testing.T) {
	cat := &Catalog{Rules: []Rule{validRule()}}
	known := func(name string) bool { return name == "nodes" }
	if errs := cat.ValidateProbes(known); len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

func TestValidateProbesFlagsUnknown(t *testing.T) {
	r := validRule()
	r.Probe = "no_such_probe"
	cat := &Catalog{Rules: []Rule{r}}
	known := func(name string) bool { return name == "nodes" }
	errs := cat.ValidateProbes(known)
	if len(errs) != 1 {
		t.Fatalf("expected one error, got %d: %v", len(errs), errs)
	}
	if !strings.Contains(errs[0].Message, "unknown probe") {
		t.Errorf("message should describe unknown probe; got %q", errs[0].Message)
	}
	if !strings.Contains(errs[0].Message, "no_such_probe") {
		t.Errorf("message should reference the probe name; got %q", errs[0].Message)
	}
	if errs[0].RuleID != r.ID {
		t.Errorf("RuleID = %q, want %q", errs[0].RuleID, r.ID)
	}
}

func TestValidateProbesSkipsEmptyProbe(t *testing.T) {
	// An empty Probe is already covered by Validate() with
	// "probe is required"; ValidateProbes must not double-report.
	r := validRule()
	r.Probe = ""
	cat := &Catalog{Rules: []Rule{r}}
	if errs := cat.ValidateProbes(func(string) bool { return false }); len(errs) != 0 {
		t.Errorf("expected no errors for empty probe (covered by Validate); got %v", errs)
	}
}

// TestValidateThroughLoader sanity-checks that loading a YAML file
// with a missing severity surfaces as a YAML error during Load (the
// Severity unmarshaller rejects unknown levels), not a Validate
// error — this pins the layering decision.
func TestValidateThroughLoader(t *testing.T) {
	const missingSeverityPasses = `
checks:
  - id: rule_one
    name: name
    category: cat
    description: desc
    probe: nodes
    condition: "true"
    message: msg
    dialects: [elasticsearch]
`
	fsys := fstest.MapFS{"rules/x.yaml": {Data: []byte(missingSeverityPasses)}}
	cat, err := LoadFS(fsys, "rules")
	if err != nil {
		t.Fatalf("LoadFS: %v", err)
	}
	// Severity left at zero → SeverityUnknown → Validate complains.
	errs := cat.Validate()
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "severity is required") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected severity-required error, got %v", errs)
	}
}
