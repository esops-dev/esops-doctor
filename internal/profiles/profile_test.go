package profiles

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/esops-dev/esops-doctor/internal/findings"
	"github.com/esops-dev/esops-doctor/internal/rules"
)

// TestEmbeddedProfilesLoadAndIncludeNamedSet is the load-bearing
// "the binary ships the documented profiles" check. The CLI's --profile
// usage hint enumerates these names; an embedded-FS regression that
// silently dropped one would make a profile invisible to operators.
func TestEmbeddedProfilesLoadAndIncludeNamedSet(t *testing.T) {
	cat, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	for _, want := range []string{"prod", "staging", "dev", "ci", "cis-bench"} {
		if _, err := cat.Get(want); err != nil {
			t.Errorf("profile %q missing: %v", want, err)
		}
	}
}

func TestGetUnknownProfileSurfacesAvailableNames(t *testing.T) {
	cat, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	_, err = cat.Get("prdo") // typo for "prod"
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
	for _, want := range []string{"unknown profile", "prdo", "prod", "cis-bench"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should contain %q", err.Error(), want)
		}
	}
}

func TestApplySeverityOverridesRewriteRuleSeverityWithoutMutatingInput(t *testing.T) {
	cat := &rules.Catalog{Rules: []rules.Rule{
		{ID: "heap_size", Severity: findings.SeverityWarn, Tags: []string{"prod"}},
		{ID: "other", Severity: findings.SeverityInfo},
	}}
	prof := &Profile{
		SeverityOverrides: map[string]findings.Severity{
			"heap_size": findings.SeverityCritical,
		},
	}
	out := prof.Apply(cat)

	if out.Rules[0].Severity != findings.SeverityCritical {
		t.Errorf("override should bump heap_size to critical; got %v", out.Rules[0].Severity)
	}
	if cat.Rules[0].Severity != findings.SeverityWarn {
		t.Errorf("input catalog mutated by Apply (was warn, now %v)", cat.Rules[0].Severity)
	}
	if out.Rules[1].Severity != findings.SeverityInfo {
		t.Errorf("non-overridden rule should keep severity; got %v", out.Rules[1].Severity)
	}
}

func TestApplyIncludeTagsNarrowsCatalog(t *testing.T) {
	cat := &rules.Catalog{Rules: []rules.Rule{
		{ID: "a", Tags: []string{"security"}},
		{ID: "b", Tags: []string{"performance"}},
		{ID: "c", Tags: []string{"security", "bootstrap"}},
		{ID: "d"},
	}}
	prof := &Profile{IncludeTags: []string{"security"}}
	out := prof.Apply(cat)

	got := ruleIDs(out)
	if len(got) != 2 || got[0] != "a" || got[1] != "c" {
		t.Errorf("include_tags=security should keep a,c; got %v", got)
	}
}

func TestApplySkipTagsWinsOverIncludeTags(t *testing.T) {
	cat := &rules.Catalog{Rules: []rules.Rule{
		{ID: "a", Tags: []string{"security"}},
		{ID: "b", Tags: []string{"security", "experimental"}},
	}}
	prof := &Profile{
		IncludeTags: []string{"security"},
		SkipTags:    []string{"experimental"},
	}
	out := prof.Apply(cat)
	got := ruleIDs(out)
	if len(got) != 1 || got[0] != "a" {
		t.Errorf("skip_tags should subtract from include_tags; got %v", got)
	}
}

func TestApplyRuleIDsRestrictsToList(t *testing.T) {
	cat := &rules.Catalog{Rules: []rules.Rule{
		{ID: "a"}, {ID: "b"}, {ID: "c"},
	}}
	prof := &Profile{RuleIDs: []string{"b"}}
	got := ruleIDs(prof.Apply(cat))
	if len(got) != 1 || got[0] != "b" {
		t.Errorf("rule_ids=b should keep only b; got %v", got)
	}
}

func TestApplyNilProfileReturnsCatalogUnchanged(t *testing.T) {
	cat := &rules.Catalog{Rules: []rules.Rule{{ID: "a"}}}
	if got := (*Profile)(nil).Apply(cat); got != cat {
		t.Errorf("nil profile should return input catalog unchanged")
	}
}

func TestLoadFSDuplicateNameRejected(t *testing.T) {
	fsys := fstest.MapFS{
		"profiles/prod.yaml":      {Data: []byte("name: prod\n")},
		"profiles/prod-copy.yaml": {Data: []byte("name: prod\n")},
	}
	_, err := LoadFS(fsys, "profiles")
	if err == nil || !strings.Contains(err.Error(), "duplicate profile") {
		t.Errorf("expected duplicate-profile error; got %v", err)
	}
}

func TestLoadFSFileStemFallbackForUnnamedProfile(t *testing.T) {
	// A profile with no `name:` should still load — the file stem is
	// the safe identifier so an operator's typo doesn't make the
	// profile silently shadow another.
	fsys := fstest.MapFS{
		"profiles/lab.yaml": {Data: []byte("description: experimental\n")},
	}
	cat, err := LoadFS(fsys, "profiles")
	if err != nil {
		t.Fatalf("LoadFS: %v", err)
	}
	if _, err := cat.Get("lab"); err != nil {
		t.Errorf("expected 'lab' fallback name; got %v", err)
	}
}

func TestUnknownSeverityOverridesFlagsTypos(t *testing.T) {
	cat := &rules.Catalog{Rules: []rules.Rule{
		{ID: "heap_size"},
		{ID: "ilm_policy", DeprecatedAliases: []string{"ilm_present"}},
	}}
	prof := &Profile{SeverityOverrides: map[string]findings.Severity{
		"heap_size":   findings.SeverityCritical, // real id — fine
		"ilm_present": findings.SeverityWarn,     // alias — fine
		"hep_size":    findings.SeverityWarn,     // typo — flag
		"renamed":     findings.SeverityInfo,     // gone — flag
	}}
	got := prof.UnknownSeverityOverrides(cat)
	if len(got) != 2 || got[0] != "hep_size" || got[1] != "renamed" {
		t.Errorf("unknown overrides should be hep_size, renamed; got %v", got)
	}
}

func TestUnknownSeverityOverridesEmptyWhenNoOverrides(t *testing.T) {
	prof := &Profile{}
	if got := prof.UnknownSeverityOverrides(&rules.Catalog{}); got != nil {
		t.Errorf("nil profile + empty catalog should produce no warnings; got %v", got)
	}
}

func ruleIDs(c *rules.Catalog) []string {
	out := make([]string, len(c.Rules))
	for i, r := range c.Rules {
		out[i] = r.ID
	}
	return out
}
