package engine

import (
	"context"
	"sync"
)

// DefaultPrefetchConcurrency is the worker count Prefetch uses when
// the caller passes 0. Picked low: the cluster behind doctor is the
// same cluster running production traffic, so a 25-rule scan should
// not look like a load test. Operators with a roomy cluster can dial
// it up explicitly.
const DefaultPrefetchConcurrency = 4

// Prefetch fans out every applicable rule's probe to the registry in
// parallel and returns a populated ProbeCache. Pass the result to
// EvaluateWithCache to skip per-rule lazy probe fetching — the
// evaluation phase becomes CPU-bound (CEL only) instead of
// network-bound.
//
// dialect filters the prefetch set: rules that don't support the
// probed cluster's dialect are skipped here too, so we never spend a
// round trip on a probe that no rule will read.
//
// concurrency caps in-flight probe fetches. <=0 means
// DefaultPrefetchConcurrency. The cap protects the cluster from a
// thundering herd when the catalog grows.
//
// Errors are not returned — they ride on the cache entries (Err
// field) and are translated to per-rule status (Skipped or Error) by
// the engine's evaluation path. ctx cancellation cuts the fan-out
// short; entries for probes that never started fetching are absent
// from the cache, and EvaluateWithCache will fall back to the lazy
// fetch path for those (which will itself observe the cancelled
// context and surface RuleStatusError).
func (e *Engine) Prefetch(ctx context.Context, registry ProbeRegistry, dialect string, concurrency int) ProbeCache {
	if concurrency <= 0 {
		concurrency = DefaultPrefetchConcurrency
	}
	probes := uniqueProbes(e.rules, dialect)
	cache := make(ProbeCache, len(probes))
	if len(probes) == 0 {
		return cache
	}

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, concurrency)
	)
scheduleLoop:
	for _, name := range probes {
		// Stop scheduling new fetches once ctx is cancelled. We still
		// need to wg.Wait() before returning so in-flight goroutines
		// finish writing to the cache map — without that wait the
		// caller observes mutation after Prefetch has returned, which
		// the race detector flags (and is genuinely unsafe).
		select {
		case <-ctx.Done():
			break scheduleLoop
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()
			data, err := registry.Probe(ctx, p)
			mu.Lock()
			cache[p] = ProbeCacheEntry{Data: data, Err: err}
			mu.Unlock()
		}(name)
	}
	wg.Wait()
	return cache
}

// uniqueProbes returns the deduplicated set of probe names referenced
// by rules applicable to dialect. Order is the first-seen catalog
// order, so prefetch debugging output reflects rule declaration
// sequence.
func uniqueProbes(rules []compiledRule, dialect string) []string {
	seen := make(map[string]struct{}, len(rules))
	out := make([]string, 0, len(rules))
	for _, cr := range rules {
		if !ruleSupportsDialect(cr.rule, dialect) {
			continue
		}
		if cr.rule.Probe == "" {
			continue
		}
		if _, ok := seen[cr.rule.Probe]; ok {
			continue
		}
		seen[cr.rule.Probe] = struct{}{}
		out = append(out, cr.rule.Probe)
	}
	return out
}
