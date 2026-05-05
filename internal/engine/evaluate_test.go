package engine

import (
	"context"
	"errors"
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

// TestEvaluateHeapSizeAgainstEmbedded is the load-bearing end-to-end
// test: the shipped heap_size rule, compiled via the engine, evaluated
// against a realistic node-stats fixture. A passing fixture must yield
// pass; a fixture with init>50%RAM must yield fail. Catches breakage
// in the rule's CEL or in the engine's data binding.
func TestEvaluateHeapSizeAgainstEmbedded(t *testing.T) {
	cat, err := rules.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	eng, err := Compile(cat)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	const gb = int64(1024 * 1024 * 1024)
	good := []any{
		map[string]any{
			"jvm": map[string]any{
				"heap": map[string]any{
					"init": int64(8) * gb,
					"max":  int64(8) * gb,
				},
			},
			"os": map[string]any{
				"total_physical_memory": int64(32) * gb,
			},
		},
	}
	bad := []any{
		map[string]any{
			"jvm": map[string]any{
				"heap": map[string]any{
					"init": int64(28) * gb, // > 50% of 32GB total
					"max":  int64(28) * gb,
				},
			},
			"os": map[string]any{
				"total_physical_memory": int64(32) * gb,
			},
		},
	}

	t.Run("good", func(t *testing.T) {
		results := eng.Evaluate(context.Background(), MapRegistry{"nodes": good}, "elasticsearch")
		if got := findStatus(results, "heap_size"); got != RuleStatusPass {
			t.Errorf("heap_size status = %v, want pass; results=%+v", got, results)
		}
	})

	t.Run("bad", func(t *testing.T) {
		results := eng.Evaluate(context.Background(), MapRegistry{"nodes": bad}, "elasticsearch")
		if got := findStatus(results, "heap_size"); got != RuleStatusFail {
			t.Errorf("heap_size status = %v, want fail", got)
		}
	})
}

func findStatus(results []RuleResult, ruleID string) RuleStatus {
	for _, r := range results {
		if r.RuleID == ruleID {
			return r.Status
		}
	}
	return RuleStatus(-1)
}
