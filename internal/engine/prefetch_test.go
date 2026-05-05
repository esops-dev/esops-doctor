package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/esops-dev/esops-doctor/internal/findings"
	"github.com/esops-dev/esops-doctor/internal/rules"
)

// parallelRegistry is a probe registry that records every Probe call
// (concurrency observed, total invocations, per-probe payload). The
// fetch sleeps to give the prefetch worker pool a real chance to
// stack calls in flight; without the sleep, fast goroutine scheduling
// can serialise the calls and hide a single-threaded regression.
type parallelRegistry struct {
	mu       sync.Mutex
	inFlight int
	maxSeen  int
	calls    map[string]int
	delay    time.Duration
	errOn    map[string]error
}

func newParallelRegistry(delay time.Duration) *parallelRegistry {
	return &parallelRegistry{
		calls: map[string]int{},
		delay: delay,
		errOn: map[string]error{},
	}
}

func (r *parallelRegistry) Probe(ctx context.Context, name string) (any, error) {
	r.mu.Lock()
	r.inFlight++
	if r.inFlight > r.maxSeen {
		r.maxSeen = r.inFlight
	}
	r.calls[name]++
	err, hasErr := r.errOn[name]
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.inFlight--
		r.mu.Unlock()
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(r.delay):
	}

	if hasErr {
		return nil, err
	}
	return fmt.Sprintf("data-for-%s", name), nil
}

func compileRules(t *testing.T, rs []rules.Rule) *Engine {
	t.Helper()
	cat := &rules.Catalog{Rules: rs}
	eng, err := Compile(cat)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return eng
}

// alwaysTrue is a CEL condition whose only job is to compile and not
// crash — Prefetch tests don't care about evaluation, only about
// which probes get fetched and how.
const alwaysTrue = `true`

func makeRule(id, probe string, dialects []string) rules.Rule {
	return rules.Rule{
		ID:        id,
		Name:      id,
		Category:  "test",
		Severity:  findings.SeverityInfo,
		Probe:     probe,
		Condition: alwaysTrue,
		Dialects:  dialects,
	}
}

// TestPrefetchDeduplicatesAndFanOutsConcurrently asserts the two
// load-bearing properties of Prefetch:
//   - one probe call per unique probe name (the second rule on the
//     same probe rides on the cache)
//   - real concurrency (delayed registry sees overlapping calls)
func TestPrefetchDeduplicatesAndFanOutsConcurrently(t *testing.T) {
	dialect := "elasticsearch"
	eng := compileRules(t, []rules.Rule{
		makeRule("a", "nodes", []string{dialect}),
		makeRule("b", "nodes", []string{dialect}), // same probe — should not double-fetch
		makeRule("c", "indices", []string{dialect}),
		makeRule("d", "cluster_health", []string{dialect}),
	})

	reg := newParallelRegistry(20 * time.Millisecond)
	cache := eng.Prefetch(context.Background(), reg, dialect, 4)

	if len(cache) != 3 {
		t.Errorf("cache size = %d, want 3 (unique probes)", len(cache))
	}
	for _, p := range []string{"nodes", "indices", "cluster_health"} {
		if reg.calls[p] != 1 {
			t.Errorf("probe %q called %d times, want 1", p, reg.calls[p])
		}
	}
	if reg.maxSeen < 2 {
		t.Errorf("expected >=2 concurrent fetches, observed peak in-flight = %d", reg.maxSeen)
	}
}

// TestPrefetchHonoursConcurrencyCap pegs the worker count and watches
// that the registry never sees more than that many calls in flight.
// Sleep dominates the call cost so the scheduler can't accidentally
// serialise them.
func TestPrefetchHonoursConcurrencyCap(t *testing.T) {
	dialect := "elasticsearch"
	var rs []rules.Rule
	for i := 0; i < 8; i++ {
		probe := fmt.Sprintf("p%d", i)
		rs = append(rs, makeRule(probe, probe, []string{dialect}))
	}
	eng := compileRules(t, rs)
	reg := newParallelRegistry(15 * time.Millisecond)

	eng.Prefetch(context.Background(), reg, dialect, 2)
	if reg.maxSeen > 2 {
		t.Errorf("concurrency cap=2 was breached: peak in-flight = %d", reg.maxSeen)
	}
}

// TestPrefetchSkipsDialectMismatchedRules: rules whose dialects don't
// include the probed cluster's dialect must not contribute to the
// prefetch set. Otherwise we waste a round trip on a probe no rule
// will read.
func TestPrefetchSkipsDialectMismatchedRules(t *testing.T) {
	eng := compileRules(t, []rules.Rule{
		makeRule("es_only", "nodes", []string{"elasticsearch"}),
		makeRule("os_only", "ism_state", []string{"opensearch"}),
	})
	reg := newParallelRegistry(0)

	cache := eng.Prefetch(context.Background(), reg, "elasticsearch", 4)
	if _, ok := cache["ism_state"]; ok {
		t.Errorf("opensearch-only probe should not be prefetched on an es scan; cache=%v", cache)
	}
	if _, ok := cache["nodes"]; !ok {
		t.Errorf("matching-dialect probe should be prefetched; cache=%v", cache)
	}
}

// TestPrefetchSurfacesProbeErrorsViaCacheEntry: a probe that errors
// out lands its error on the cache entry. The engine's evaluate path
// then translates that into RuleStatusError or Skipped (depending on
// sentinel); Prefetch itself never returns an error.
func TestPrefetchSurfacesProbeErrorsViaCacheEntry(t *testing.T) {
	dialect := "elasticsearch"
	eng := compileRules(t, []rules.Rule{
		makeRule("ok", "nodes", []string{dialect}),
		makeRule("bad", "indices", []string{dialect}),
	})
	reg := newParallelRegistry(0)
	reg.errOn["indices"] = errors.New("transport: connection refused")

	cache := eng.Prefetch(context.Background(), reg, dialect, 4)
	if cache["nodes"].Err != nil {
		t.Errorf("ok probe should not have err; got %v", cache["nodes"].Err)
	}
	if cache["indices"].Err == nil || cache["indices"].Err.Error() != "transport: connection refused" {
		t.Errorf("err probe should carry its error; got %v", cache["indices"].Err)
	}
}

// TestPrefetchStopsSchedulingOnCancel: if ctx is cancelled before
// every probe is dispatched, Prefetch returns promptly with whatever
// it already has. EvaluateWithCache will then lazy-fetch for the
// missing probes and observe the cancelled context itself.
func TestPrefetchStopsSchedulingOnCancel(t *testing.T) {
	dialect := "elasticsearch"
	var rs []rules.Rule
	for i := 0; i < 20; i++ {
		probe := fmt.Sprintf("p%d", i)
		rs = append(rs, makeRule(probe, probe, []string{dialect}))
	}
	eng := compileRules(t, rs)

	reg := newParallelRegistry(50 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	var dispatched atomic.Int32
	wrapped := &dispatchCounting{inner: reg, dispatched: &dispatched}
	cache := eng.Prefetch(ctx, wrapped, dialect, 2)

	// The cancel is racy by design; assert the safety properties:
	//   - we did NOT dispatch every probe (cancel ate some scheduling)
	//   - whatever did dispatch landed on the cache, possibly with
	//     ctx.Canceled errors
	if dispatched.Load() >= int32(len(rs)) {
		t.Errorf("expected fewer dispatches than rules; got %d/%d", dispatched.Load(), len(rs))
	}
	if len(cache) > int(dispatched.Load()) {
		t.Errorf("cache has more entries (%d) than dispatched probes (%d)", len(cache), dispatched.Load())
	}
}

// dispatchCounting wraps a registry to count how many Probe
// calls were dispatched (entered) versus completed. Distinguishes
// "scheduled" from "completed" — the cancel test cares about the
// former.
type dispatchCounting struct {
	inner      ProbeRegistry
	dispatched *atomic.Int32
}

func (d *dispatchCounting) Probe(ctx context.Context, name string) (any, error) {
	d.dispatched.Add(1)
	return d.inner.Probe(ctx, name)
}
