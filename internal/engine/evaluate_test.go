package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/esops-dev/esops-doctor/internal/findings"
	"github.com/esops-dev/esops-doctor/internal/rules"
)

func mustCompile(t *testing.T, rs ...rules.Rule) *Engine {
	t.Helper()
	eng, err := Compile(&rules.Catalog{Rules: rs})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return eng
}

func TestEvaluatePass(t *testing.T) {
	eng := mustCompile(t, validRule("r1", "size(self) > 0"))
	registry := MapRegistry{"nodes": []any{"a"}}
	results := eng.Evaluate(context.Background(), registry, "elasticsearch")
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if results[0].Status != RuleStatusPass {
		t.Errorf("Status = %v, want pass", results[0].Status)
	}
	if results[0].Finding != nil {
		t.Errorf("Finding should be nil on pass; got %+v", results[0].Finding)
	}
}

func TestEvaluateFailEmitsFinding(t *testing.T) {
	r := validRule("r1", "size(self) > 0")
	r.Severity = findings.SeverityCritical
	r.Message = "no nodes returned by probe"
	eng := mustCompile(t, r)
	registry := MapRegistry{"nodes": []any{}}
	results := eng.Evaluate(context.Background(), registry, "elasticsearch")
	if results[0].Status != RuleStatusFail {
		t.Fatalf("Status = %v, want fail", results[0].Status)
	}
	f := results[0].Finding
	if f == nil {
		t.Fatal("Finding should be populated on fail")
	}
	if f.Severity != findings.SeverityCritical {
		t.Errorf("Severity = %v, want critical", f.Severity)
	}
	if f.Dialect != "elasticsearch" {
		t.Errorf("Dialect = %q, want elasticsearch", f.Dialect)
	}
	if f.Message != "no nodes returned by probe" {
		t.Errorf("Message = %q, want literal pass-through", f.Message)
	}
}

func TestEvaluateSkipsWrongDialect(t *testing.T) {
	r := validRule("r1", "size(self) > 0")
	r.Dialects = []string{"opensearch"}
	eng := mustCompile(t, r)
	registry := MapRegistry{"nodes": []any{}}
	results := eng.Evaluate(context.Background(), registry, "elasticsearch")
	if results[0].Status != RuleStatusSkipped {
		t.Errorf("Status = %v, want skipped", results[0].Status)
	}
	if !strings.Contains(results[0].SkipReason, "dialect") {
		t.Errorf("SkipReason should mention dialect; got %q", results[0].SkipReason)
	}
}

func TestEvaluateSkipsUnknownProbe(t *testing.T) {
	r := validRule("r1", "size(self) > 0")
	r.Probe = "no_such_probe"
	eng := mustCompile(t, r)
	registry := MapRegistry{}
	results := eng.Evaluate(context.Background(), registry, "elasticsearch")
	if results[0].Status != RuleStatusSkipped {
		t.Errorf("Status = %v, want skipped", results[0].Status)
	}
	if !strings.Contains(results[0].SkipReason, "no_such_probe") {
		t.Errorf("SkipReason should mention probe name; got %q", results[0].SkipReason)
	}
}

// failingRegistry returns a non-sentinel error to verify it lands as
// RuleStatusError, not Skipped.
type failingRegistry struct{ err error }

func (f failingRegistry) Probe(_ context.Context, _ string) (any, error) {
	return nil, f.err
}

// notApplicableRegistry returns ErrProbeNotApplicable wrapped with a
// dialect-specific cause — the shape probes.Registry produces when it
// translates the upstream client.ErrUnsupported sentinel.
type notApplicableRegistry struct{ cause error }

func (r notApplicableRegistry) Probe(_ context.Context, _ string) (any, error) {
	return nil, fmt.Errorf("%w: %w", ErrProbeNotApplicable, r.cause)
}

// TestEvaluateNotApplicableSkipsWithDialectReason asserts that a probe
// returning ErrProbeNotApplicable (the shape probes.Registry produces
// when it translates client.ErrUnsupported — ILM on OS, ISM on ES,
// deprecation_log on OS) lands as Skipped, not Error, and the
// SkipReason carries the dialect plus the underlying cause.
//
// Distinct from the dialect-mismatch skip path (which fires before the
// probe is even called, on rules.Dialects vs. cluster dialect): this
// fires when a rule legitimately applies to both products but the
// cluster's adapter cannot serve the data.
func TestEvaluateNotApplicableSkipsWithDialectReason(t *testing.T) {
	eng := mustCompile(t, validRule("r1", "size(self) > 0"))
	cause := errors.New("ILM is Elasticsearch-only")
	registry := notApplicableRegistry{cause: cause}

	results := eng.Evaluate(context.Background(), registry, "opensearch")
	if results[0].Status != RuleStatusSkipped {
		t.Errorf("Status = %v, want skipped", results[0].Status)
	}
	for _, want := range []string{"opensearch", "ILM is Elasticsearch-only", `"nodes"`} {
		if !strings.Contains(results[0].SkipReason, want) {
			t.Errorf("SkipReason = %q, want it to contain %q", results[0].SkipReason, want)
		}
	}
}

func TestEvaluateProbeFetchErrorIsError(t *testing.T) {
	eng := mustCompile(t, validRule("r1", "size(self) > 0"))
	registry := failingRegistry{err: errors.New("network unreachable")}
	results := eng.Evaluate(context.Background(), registry, "elasticsearch")
	if results[0].Status != RuleStatusError {
		t.Errorf("Status = %v, want error", results[0].Status)
	}
	if !strings.Contains(results[0].Err.Error(), "network unreachable") {
		t.Errorf("Err should wrap underlying message; got %v", results[0].Err)
	}
}

// countingRegistry records how many times each probe was queried, so
// the cache-once-per-scan contract is verifiable.
type countingRegistry struct {
	data  any
	calls map[string]int
}

func (c *countingRegistry) Probe(_ context.Context, name string) (any, error) {
	if c.calls == nil {
		c.calls = map[string]int{}
	}
	c.calls[name]++
	return c.data, nil
}

func TestEvaluateCachesProbePerScan(t *testing.T) {
	eng := mustCompile(t,
		validRule("r1", "size(self) > 0"),
		validRule("r2", "size(self) > 0"),
		validRule("r3", "size(self) > 0"),
	)
	reg := &countingRegistry{data: []any{"a"}}
	_ = eng.Evaluate(context.Background(), reg, "elasticsearch")
	if reg.calls["nodes"] != 1 {
		t.Errorf("probe fetched %d time(s); want 1 (cache should fold 3 rules into 1 fetch)", reg.calls["nodes"])
	}
}

func TestEvaluateCancelledContext(t *testing.T) {
	eng := mustCompile(t, validRule("r1", "size(self) > 0"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results := eng.Evaluate(ctx, MapRegistry{"nodes": []any{}}, "elasticsearch")
	if results[0].Status != RuleStatusError {
		t.Errorf("Status = %v, want error from cancelled ctx", results[0].Status)
	}
	if !errors.Is(results[0].Err, context.Canceled) {
		t.Errorf("Err should match context.Canceled; got %v", results[0].Err)
	}
}

func TestEvaluateMessageCountTemplating(t *testing.T) {
	r := validRule("r1", "false") // always fails
	r.Message = "found {{count}} nodes"
	eng := mustCompile(t, r)
	registry := MapRegistry{"nodes": []any{"a", "b", "c"}}
	results := eng.Evaluate(context.Background(), registry, "elasticsearch")
	if results[0].Finding.Message != "found 3 nodes" {
		t.Errorf("templated message = %q, want \"found 3 nodes\"", results[0].Finding.Message)
	}
}

func TestEvaluateMessageCountTemplatingNonList(t *testing.T) {
	r := validRule("r1", "false")
	r.Message = "value: {{count}}"
	eng := mustCompile(t, r)
	registry := MapRegistry{"nodes": 42} // scalar; selfSize → 0
	results := eng.Evaluate(context.Background(), registry, "elasticsearch")
	if results[0].Finding.Message != "value: 0" {
		t.Errorf("templated message = %q, want \"value: 0\"", results[0].Finding.Message)
	}
}

// TestCountExpressionFeedsMessage locks the count_expression contract:
// when present, the rule's message {{count}} is the result of the
// expression, not len(self). Without this the heap_size message would
// say "misconfigured on 3 nodes" against a 3-node cluster where only
// 1 is broken.
func TestCountExpressionFeedsMessage(t *testing.T) {
	r := validRule("r1", "size(self.filter(n, n != 'bad')) == size(self)")
	r.Message = "{{count}} bad nodes"
	r.CountExpression = "size(self.filter(n, n == 'bad'))"
	eng := mustCompile(t, r)

	// 3 nodes, one named "bad" — condition fails (because all-good is
	// false), count_expression returns 1.
	registry := MapRegistry{"nodes": []any{"a", "bad", "b"}}
	results := eng.Evaluate(context.Background(), registry, "elasticsearch")
	if results[0].Status != RuleStatusFail {
		t.Fatalf("expected fail; got %v", results[0].Status)
	}
	if got := results[0].Finding.Message; got != "1 bad nodes" {
		t.Errorf("count_expression should drive {{count}} = 1; got %q", got)
	}
}

// TestCountExpressionMissingFallsBackToSelfSize locks the
// backwards-compat path: rules without count_expression keep the
// pre-existing len(self) substitution behaviour.
func TestCountExpressionMissingFallsBackToSelfSize(t *testing.T) {
	r := validRule("r1", "size(self) == 0")
	r.Message = "{{count}} items"
	eng := mustCompile(t, r)

	registry := MapRegistry{"nodes": []any{"a", "b", "c"}}
	results := eng.Evaluate(context.Background(), registry, "elasticsearch")
	if got := results[0].Finding.Message; got != "3 items" {
		t.Errorf("missing count_expression should fall back to len(self); got %q", got)
	}
}

// TestCompileRejectsNonIntCountExpression — a catalog bug where the
// count_expression returns the wrong type should fail at validate
// time, not at scan time. Compile aggregates failures so the operator
// sees every issue in one pass.
func TestCompileRejectsNonIntCountExpression(t *testing.T) {
	r := validRule("r1", "size(self) > 0")
	r.CountExpression = `"a string, not an int"`
	_, err := Compile(&rules.Catalog{Rules: []rules.Rule{r}})
	if err == nil {
		t.Fatal("expected compile failure for string count_expression")
	}
	var ce *CompileError
	if !errors.As(err, &ce) {
		t.Fatalf("expected CompileError; got %T", err)
	}
	if !strings.Contains(ce.Failures[0].Message, "count_expression") {
		t.Errorf("failure should call out count_expression; got %q", ce.Failures[0].Message)
	}
}
