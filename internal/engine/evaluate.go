package engine

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"

	"github.com/esops-dev/esops-doctor/internal/findings"
	"github.com/esops-dev/esops-doctor/internal/rules"
)

// ProbeCacheEntry is one cached probe result. Exported so callers can
// pre-populate it via Prefetch and pass it into EvaluateWithCache,
// turning the engine's per-rule lazy fetch into a parallel pre-fetch.
type ProbeCacheEntry struct {
	Data any
	Err  error
}

// ProbeCache is the engine's per-evaluation cache, keyed by probe
// name. A nil cache passed to EvaluateWithCache is equivalent to
// Evaluate (lazy fan-in fetching).
type ProbeCache map[string]ProbeCacheEntry

// Evaluate runs every compiled rule against the probe registry. The
// dialect parameter is the probed cluster's dialect ("elasticsearch"
// or "opensearch"); rules whose dialects list does not include it are
// skipped with a documented reason.
//
// Probe data is fetched at most once per scan: the second rule asking
// for "nodes" reuses the data the first rule received, including its
// error. ctx is propagated to both ProbeRegistry.Probe and
// cel.Program.ContextEval, so cancellation kills an in-flight scan
// promptly.
//
// For parallel pre-fetching call Prefetch first and pass the result
// to EvaluateWithCache; this method is the lazy-fetch convenience.
func (e *Engine) Evaluate(ctx context.Context, registry ProbeRegistry, dialect string) []RuleResult {
	return e.EvaluateWithCache(ctx, registry, dialect, nil)
}

// EvaluateWithCache is Evaluate with a pre-populated probe cache.
// Cache entries are reused as-is (including their errors); probes
// missing from the cache fall back to the lazy fetch path.
//
// Pre-populating the cache via Prefetch parallelises the
// network-bound part of a scan: a 25-rule catalog hitting 12 unique
// probes goes from 12 sequential round trips to one fan-out batch
// bounded by Prefetch's concurrency limit.
func (e *Engine) EvaluateWithCache(ctx context.Context, registry ProbeRegistry, dialect string, cache ProbeCache) []RuleResult {
	if cache == nil {
		cache = ProbeCache{}
	}
	results := make([]RuleResult, 0, len(e.rules))
	for _, cr := range e.rules {
		if err := ctx.Err(); err != nil {
			results = append(results, RuleResult{
				RuleID: cr.rule.ID,
				Rule:   cr.rule,
				Status: RuleStatusError,
				Err:    err,
			})
			continue
		}
		results = append(results, evalOne(ctx, cr, registry, dialect, cache))
	}
	return results
}

func evalOne(ctx context.Context, cr compiledRule, registry ProbeRegistry, dialect string, cache ProbeCache) RuleResult {
	start := time.Now()
	res := RuleResult{RuleID: cr.rule.ID, Rule: cr.rule}
	defer func() { res.Duration = time.Since(start) }()

	if !ruleSupportsDialect(cr.rule, dialect) {
		res.Status = RuleStatusSkipped
		res.SkipReason = fmt.Sprintf("rule does not support dialect %q (declared: %s)",
			dialect, strings.Join(cr.rule.Dialects, ", "))
		return res
	}

	entry, ok := cache[cr.rule.Probe]
	if !ok {
		data, err := registry.Probe(ctx, cr.rule.Probe)
		entry = ProbeCacheEntry{Data: data, Err: err}
		cache[cr.rule.Probe] = entry
	}
	if entry.Err != nil {
		if errors.Is(entry.Err, ErrProbeNotFound) {
			res.Status = RuleStatusSkipped
			res.SkipReason = fmt.Sprintf("probe %q not registered", cr.rule.Probe)
			return res
		}
		if errors.Is(entry.Err, ErrProbeNotApplicable) {
			res.Status = RuleStatusSkipped
			res.SkipReason = fmt.Sprintf("probe %q not applicable on dialect %q: %s",
				cr.rule.Probe, dialect, entry.Err)
			return res
		}
		res.Status = RuleStatusError
		res.Err = fmt.Errorf("fetching probe %q: %w", cr.rule.Probe, entry.Err)
		return res
	}

	out, _, err := cr.prog.ContextEval(ctx, map[string]any{"self": entry.Data})
	if err != nil {
		res.Status = RuleStatusError
		res.Err = fmt.Errorf("evaluating: %w", err)
		return res
	}
	pass, ok := out.Value().(bool)
	if !ok {
		res.Status = RuleStatusError
		res.Err = fmt.Errorf("condition returned non-bool: %T", out.Value())
		return res
	}
	if pass {
		res.Status = RuleStatusPass
		return res
	}

	res.Status = RuleStatusFail
	finding := findings.Finding{
		RuleID:      cr.rule.ID,
		Name:        cr.rule.Name,
		Severity:    cr.rule.Severity,
		Category:    cr.rule.Category,
		Message:     renderMessage(ctx, cr, entry.Data),
		Remediation: cr.rule.Remediation,
		Dialect:     dialect,
	}
	res.Finding = &finding
	return res
}

func ruleSupportsDialect(r rules.Rule, dialect string) bool {
	for _, d := range r.Dialects {
		if d == dialect {
			return true
		}
	}
	return false
}

// renderMessage substitutes the v0.1 message placeholders.
// {{count}} resolves to the rule's count_expression result when one
// was declared, falling back to len(self) for backwards compatibility.
//
// The fallback is "self size" rather than "failing-item count" because
// the engine only sees one boolean from the condition; rules that want
// the precise failing count declare a count_expression CEL filter.
// Evaluation errors on count_expression are not fatal — the renderer
// falls back to len(self) and a debug-friendly trail (the original
// error is dropped, but the rule's failure is the operator-actionable
// signal, not the count itself).
func renderMessage(ctx context.Context, cr compiledRule, data any) string {
	return strings.ReplaceAll(cr.rule.Message, "{{count}}",
		fmt.Sprintf("%d", evalCount(ctx, cr, data)))
}

func evalCount(ctx context.Context, cr compiledRule, data any) int64 {
	if cr.countProg == nil {
		return int64(selfSize(data))
	}
	out, _, err := cr.countProg.ContextEval(ctx, map[string]any{"self": data})
	if err != nil {
		return int64(selfSize(data))
	}
	switch v := out.Value().(type) {
	case int64:
		return v
	case uint64:
		// CEL's uint can grow beyond int64 in principle. In practice
		// rules count items in a probe response (always tiny relative
		// to MaxInt64); clamp rather than overflow so a hostile rule
		// can't silently make the message say "-9223372036854775808".
		if v > math.MaxInt64 {
			return math.MaxInt64
		}
		return int64(v)
	case int:
		return int64(v)
	default:
		return int64(selfSize(data))
	}
}

func selfSize(data any) int {
	if data == nil {
		return 0
	}
	v := reflect.ValueOf(data)
	switch v.Kind() {
	case reflect.Slice, reflect.Array, reflect.Map, reflect.String:
		return v.Len()
	default:
		return 0
	}
}
