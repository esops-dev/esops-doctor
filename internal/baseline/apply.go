package baseline

import (
	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/findings"
)

// DriftReason classifies why a baseline entry didn't match the
// current run. Stable enum strings so a downstream that filters
// drift entries by reason can rely on them.
type DriftReason string

const (
	// DriftRuleUnknown — the baseline entry names a rule that is no
	// longer in the running catalog (renamed, retired, or never in
	// the catalog the baseline was written against). Warning, not an
	// error: rule retirements happen.
	DriftRuleUnknown DriftReason = "rule_unknown"

	// DriftDidNotFire — the baseline entry's rule did run but did not
	// fail in the current scan. Either the underlying problem was
	// fixed (good) or the rule's condition changed; either way the
	// baseline entry no longer suppresses anything.
	DriftDidNotFire DriftReason = "did_not_fire"
)

// DriftEntry is one baseline-side artefact that no longer matches a
// current finding. Reported so baselines don't rot silently — an
// expired waiver loud, a stale baseline entry loud.
type DriftEntry struct {
	Entry  Entry
	Reason DriftReason
}

// Apply walks results and, for every fail whose fingerprint matches a
// baseline entry, attaches a Finding.Baseline marker. Returns the
// drift entries the baseline carried but the current scan did not
// fail on — see DriftReason for the classification.
//
// Apply does not modify Findings beyond setting Baseline; severity,
// message, and Suppression all round-trip untouched. A finding with
// both a Baseline and a Suppression keeps the waiver semantics
// (Suppression already exempts it from the fail-on gate); the
// Baseline marker is informational in that case.
//
// catalogRules is the set of rule IDs present in the running
// catalog. Used to split "rule retired" drift from "rule ran but
// passed" drift. Pass nil to skip the rule-known check — every
// missing-match entry then reports as DriftDidNotFire.
func (s *Set) Apply(results []engine.RuleResult, catalogRules map[string]bool) []DriftEntry {
	if s.Empty() {
		return nil
	}

	matched := make(map[string]bool, len(s.entries))

	// firedRules: the set of rule IDs that produced a fail in this
	// scan. A baseline entry whose rule fired but with a different
	// fingerprint (e.g. target changed) doesn't show up in matched[]
	// but the rule did fire — report it as did_not_fire-at-this-target
	// rather than rule_unknown so the operator's mental model lines
	// up with the SARIF/JSON they're holding.
	firedRules := make(map[string]bool)

	for i := range results {
		r := &results[i]
		if r.Status != engine.RuleStatusFail || r.Finding == nil {
			continue
		}
		firedRules[r.RuleID] = true

		fp := Fingerprint{
			RuleID:  r.RuleID,
			Dialect: r.Finding.Dialect,
		}
		if _, ok := s.entries[fp.Key()]; ok {
			matched[fp.Key()] = true
			r.Finding.Baseline = &findings.BaselineMatch{Source: s.source}
			continue
		}
		// Try the dialect-agnostic form: baselines harvested from a
		// SARIF doc that didn't embed a dialect property collapse to
		// (rule_id, ""). Match those too so legacy SARIF still
		// suppresses today's findings.
		fpNoDialect := Fingerprint{RuleID: r.RuleID}
		if _, ok := s.entries[fpNoDialect.Key()]; ok {
			matched[fpNoDialect.Key()] = true
			r.Finding.Baseline = &findings.BaselineMatch{Source: s.source}
		}
	}

	var drift []DriftEntry
	for key, e := range s.entries {
		if matched[key] {
			continue
		}
		reason := DriftDidNotFire
		if catalogRules != nil && !catalogRules[e.Fingerprint.RuleID] {
			reason = DriftRuleUnknown
		} else if !firedRules[e.Fingerprint.RuleID] {
			// Rule exists in the catalog but didn't fail at all in
			// this scan. did_not_fire is the right reason.
			reason = DriftDidNotFire
		}
		drift = append(drift, DriftEntry{Entry: e, Reason: reason})
	}
	return drift
}

// MaxBaselineSeverity returns the most urgent severity across
// findings.Baseline-flagged failures. Useful for a "you suppressed N
// at severity X" diagnostic; the fail-on gate already excludes them.
func MaxBaselineSeverity(results []engine.RuleResult) findings.Severity {
	max := findings.SeverityUnknown
	for _, r := range results {
		if r.Status != engine.RuleStatusFail || r.Finding == nil {
			continue
		}
		if r.Finding.Baseline == nil {
			continue
		}
		if r.Finding.Severity > max {
			max = r.Finding.Severity
		}
	}
	return max
}

// AppliedCount returns the number of findings carrying a Baseline
// match. Used by the cli for log lines without re-walking results.
func AppliedCount(results []engine.RuleResult) int {
	n := 0
	for _, r := range results {
		if r.Finding != nil && r.Finding.Baseline != nil {
			n++
		}
	}
	return n
}
