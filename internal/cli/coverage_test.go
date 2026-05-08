package cli

import (
	"sort"
	"strings"
	"testing"

	"github.com/esops-dev/esops-doctor/internal/findings"
	"github.com/esops-dev/esops-doctor/internal/rules"
)

// rule is a tiny constructor for tests so the table cases stay
// readable without the full schema noise.
func makeRule(id string, tags ...string) rules.Rule {
	return rules.Rule{
		ID:       id,
		Severity: findings.SeverityError,
		Tags:     tags,
	}
}

// TestComputeCoverageCountsPresentAndMissing exercises the per-bucket
// arithmetic: a rule listed in a bucket lands in Present iff it
// exists in the catalog, otherwise in Missing. Buckets the rule does
// NOT name leave it untouched. Catches a regression where a future
// refactor of the bucket list silently double-counts or drops a
// member.
func TestComputeCoverageCountsPresentAndMissing(t *testing.T) {
	// Pull two member IDs from real buckets and one bogus ID. Any
	// existing-bucket members work — the test only cares about the
	// arithmetic, not which bucket the IDs live in.
	if len(coverageBuckets) == 0 {
		t.Fatal("coverageBuckets must not be empty")
	}
	var sampleA, sampleB string
	for _, b := range coverageBuckets {
		for _, m := range b.Members {
			if sampleA == "" {
				sampleA = m
				continue
			}
			if sampleB == "" && m != sampleA {
				sampleB = m
			}
		}
	}
	if sampleA == "" || sampleB == "" {
		t.Fatal("could not find two distinct bucket members; bucket list too small")
	}

	doc := computeCoverage([]rules.Rule{
		makeRule(sampleA),
		// sampleB intentionally absent so it lands in Missing.
		makeRule("custom_rule_outside_any_bucket"),
	})

	// Spot-check that sampleA appears in some bucket's Present list and
	// sampleB appears in some bucket's Missing list.
	var foundPresent, foundMissing bool
	for _, b := range doc.Buckets {
		for _, id := range b.Present {
			if id == sampleA {
				foundPresent = true
			}
		}
		for _, id := range b.Missing {
			if id == sampleB {
				foundMissing = true
			}
		}
	}
	if !foundPresent {
		t.Errorf("expected %q in some bucket's Present list", sampleA)
	}
	if !foundMissing {
		t.Errorf("expected %q in some bucket's Missing list", sampleB)
	}

	// A rule the bucket list does not name lands in Unbucketed.
	var foundUnbucketed bool
	for _, id := range doc.Unbucketed {
		if id == "custom_rule_outside_any_bucket" {
			foundUnbucketed = true
			break
		}
	}
	if !foundUnbucketed {
		t.Errorf("expected custom_rule_outside_any_bucket in Unbucketed; got %v", doc.Unbucketed)
	}
}

// TestComputeCoverageBucketTotalsMatchMembers asserts each bucket's
// Total matches the length of its Members list and Covered+len(Missing)
// equals Total, regardless of input. This is the load-bearing
// invariant for a downstream gate that compares Covered/Total ratios.
func TestComputeCoverageBucketTotalsMatchMembers(t *testing.T) {
	doc := computeCoverage(nil) // empty catalog: every member is Missing.
	for _, b := range doc.Buckets {
		want := 0
		for _, bb := range coverageBuckets {
			if bb.ID == b.Bucket {
				want = len(bb.Members)
				break
			}
		}
		if b.Total != want {
			t.Errorf("bucket %q: Total=%d, want %d", b.Bucket, b.Total, want)
		}
		if b.Covered+len(b.Missing) != b.Total {
			t.Errorf("bucket %q: Covered(%d)+Missing(%d) != Total(%d)",
				b.Bucket, b.Covered, len(b.Missing), b.Total)
		}
		if b.Covered != 0 {
			t.Errorf("bucket %q: empty catalog should give Covered=0; got %d", b.Bucket, b.Covered)
		}
	}
}

// TestCoverageBucketsListedInOrder asserts the rendered buckets keep
// their declaration order. The tabular output is operator-facing and
// the bucket order matches the design scope's enumeration; reordering
// silently would muddle every downstream report.
func TestCoverageBucketsListedInOrder(t *testing.T) {
	doc := computeCoverage(nil)
	if len(doc.Buckets) != len(coverageBuckets) {
		t.Fatalf("rendered %d buckets, declared %d", len(doc.Buckets), len(coverageBuckets))
	}
	for i, b := range doc.Buckets {
		if b.Bucket != coverageBuckets[i].ID {
			t.Errorf("bucket[%d].ID = %q, want %q", i, b.Bucket, coverageBuckets[i].ID)
		}
	}
}

// TestCoverageBucketsHaveUniqueIDs catches a copy-paste typo in the
// bucket list — same ID twice would conflate two distinct §1 buckets
// in the rendered output.
func TestCoverageBucketsHaveUniqueIDs(t *testing.T) {
	seen := make(map[string]struct{})
	for _, b := range coverageBuckets {
		if _, ok := seen[b.ID]; ok {
			t.Errorf("duplicate bucket id %q", b.ID)
		}
		seen[b.ID] = struct{}{}
	}
}

// TestEveryCatalogRuleIsBucketed enforces the contract that the
// bucket list owns: every shipped rule must appear in at least one
// bucket. Adding a rule without listing it in a bucket fails this
// test loudly so a maintainer notices the catalog drift before the
// next coverage report renders the rule as "unbucketed".
func TestEveryCatalogRuleIsBucketed(t *testing.T) {
	cat, err := loadLayeredCatalog("")
	if err != nil {
		t.Fatalf("loadLayeredCatalog: %v", err)
	}
	doc := computeCoverage(cat.Rules)
	if len(doc.Unbucketed) > 0 {
		sort.Strings(doc.Unbucketed)
		t.Fatalf("the following rule(s) are in the catalog but not assigned to any "+
			"bucket in internal/cli/coverage.go — add them to the appropriate "+
			"coverageBuckets entry: %s", strings.Join(doc.Unbucketed, ", "))
	}
}
