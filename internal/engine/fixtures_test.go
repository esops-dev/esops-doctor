package engine

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	"github.com/esops-dev/esops-doctor/internal/rules"
)

// fixtureCase is one passing or failing input row for a rule. Data is
// the probe payload the rule's CEL condition will see as `self`,
// already shaped the way jsonShape produces (snake_case maps and
// slices). Dialect defaults to "elasticsearch" when empty so the
// common case stays terse.
type fixtureCase struct {
	Name    string `yaml:"name"`
	Expect  string `yaml:"expect"` // pass | fail | skipped
	Dialect string `yaml:"dialect,omitempty"`
	Data    any    `yaml:"data"`
}

// fixtureFile is the per-rule fixture file shape. Rule must match the
// rule ID; Cases must contain at least one pass and one fail entry to
// satisfy the catalog-hygiene contract — the CI step that fails when
// any rule lacks a fixture-based test.
type fixtureFile struct {
	Rule  string        `yaml:"rule"`
	Cases []fixtureCase `yaml:"cases"`
}

// fixturesDir is the on-disk location of per-rule fixture YAMLs. Tests
// in this file resolve it relative to the engine package.
const fixturesDir = "../../testdata/rule_fixtures"

// TestEveryRuleHasFixtures is the load-bearing catalog-hygiene gate.
// For every rule in the embedded catalog, it asserts a fixture file
// exists with at least one pass case and one fail case, and that every
// case evaluates to its declared outcome through the real engine.
//
// Adding a rule without fixtures fails this test loudly — that is the
// "CI step that fails when any rule lacks a fixture-based test" the
// roadmap calls for.
func TestEveryRuleHasFixtures(t *testing.T) {
	cat, err := rules.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	eng, err := Compile(cat)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	// Index the catalog by rule ID so each fixture file's `rule:` key
	// can be cross-checked, and so the test reports unknown-rule
	// fixtures rather than silently ignoring them.
	byID := make(map[string]rules.Rule, len(cat.Rules))
	for _, r := range cat.Rules {
		byID[r.ID] = r
	}

	for _, r := range cat.Rules {
		t.Run(r.ID, func(t *testing.T) {
			ff := loadFixture(t, r.ID)
			if ff.Rule != r.ID {
				t.Fatalf("fixture rule = %q, want %q", ff.Rule, r.ID)
			}

			var hasPass, hasFail bool
			for _, c := range ff.Cases {
				switch strings.ToLower(c.Expect) {
				case "pass":
					hasPass = true
				case "fail":
					hasFail = true
				}
			}
			if !hasPass || !hasFail {
				t.Fatalf("fixture must contain at least one pass case and one fail case "+
					"(have pass=%v, fail=%v)", hasPass, hasFail)
			}

			for _, c := range ff.Cases {
				t.Run(c.Name, func(t *testing.T) {
					runFixtureCase(t, eng, r, c)
				})
			}
		})
	}

	// Surface fixture files that don't correspond to any catalog rule
	// — typically a leftover after a rename. One pass, deterministic
	// order so the message is reproducible.
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Fatalf("read fixtures dir: %v", err)
	}
	var orphans []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".yaml")
		if _, ok := byID[id]; !ok {
			orphans = append(orphans, e.Name())
		}
	}
	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Errorf("orphan fixture files (no matching rule): %s", strings.Join(orphans, ", "))
	}
}

// loadFixture reads testdata/rule_fixtures/<id>.yaml and parses it.
// Missing file is a hard failure — the catalog-hygiene contract is
// "every rule has a fixture", and the test message should make the
// remediation obvious.
func loadFixture(t *testing.T, ruleID string) fixtureFile {
	t.Helper()
	path := filepath.Join(fixturesDir, ruleID+".yaml")
	data, err := os.ReadFile(path) //nolint:gosec // test path
	if err != nil {
		t.Fatalf("rule %q has no fixture file at %s: %v", ruleID, path, err)
	}
	var ff fixtureFile
	if err := yaml.Unmarshal(data, &ff); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return ff
}

// runFixtureCase evaluates one fixture case through Compile + Evaluate
// and asserts the rule's status matches the expected outcome. Data is
// passed verbatim — the rule author's responsibility is to write the
// fixture in the same JSON shape the real probe produces.
func runFixtureCase(t *testing.T, eng *Engine, r rules.Rule, c fixtureCase) {
	t.Helper()

	dialect := c.Dialect
	if dialect == "" {
		// Default to a dialect the rule supports — "elasticsearch" if
		// listed, else the first declared dialect. Avoids fixture
		// authors having to repeat dialect on every case for OS-only
		// rules.
		dialect = "elasticsearch"
		supports := false
		for _, d := range r.Dialects {
			if d == dialect {
				supports = true
				break
			}
		}
		if !supports && len(r.Dialects) > 0 {
			dialect = r.Dialects[0]
		}
	}

	registry := MapRegistry{r.Probe: c.Data}
	results := eng.Evaluate(context.Background(), registry, dialect)

	var got RuleResult
	for _, res := range results {
		if res.RuleID == r.ID {
			got = res
			break
		}
	}

	want := strings.ToLower(c.Expect)
	gotStatus := got.Status.String()
	if want == "pass" && gotStatus != "pass" {
		t.Errorf("expected pass, got %s (err=%v, skip=%q)", gotStatus, got.Err, got.SkipReason)
	}
	if want == "fail" && gotStatus != "fail" {
		t.Errorf("expected fail, got %s (err=%v, skip=%q)", gotStatus, got.Err, got.SkipReason)
	}
	if want == "skipped" && gotStatus != "skipped" {
		t.Errorf("expected skipped, got %s (err=%v)", gotStatus, got.Err)
	}
	if want != "pass" && want != "fail" && want != "skipped" {
		t.Errorf("unknown expect %q in fixture (want pass|fail|skipped)", c.Expect)
	}

	// On a fail, the engine should have populated a Finding whose
	// severity matches the rule. Worth asserting once per case so a
	// regression in finding wiring doesn't pass these tests silently.
	if want == "fail" && got.Finding == nil {
		t.Errorf("fail case should produce a Finding, got nil")
	}
	if want == "fail" && got.Finding != nil && got.Finding.Severity != r.Severity {
		t.Errorf("finding severity = %s, want %s", got.Finding.Severity, r.Severity)
	}
}
