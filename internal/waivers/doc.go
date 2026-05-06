// Package waivers loads operator-supplied finding suppressions and
// matches them against engine results.
//
// A waiver is a documented exception: rule X is allowed to fail because
// "we know about it; here's why". Each waiver carries a required
// justification and an optional expires_at. Expired waivers fail loud
// (the finding re-surfaces with a "waiver expired" note prepended to
// the message) so the suppression cannot rot silently — CLAUDE.md §9.
//
// Concurrency: Set.Apply mutates each matched RuleResult.Finding in
// place. Callers that render results in parallel must call Apply
// before fanning out, or guard the slice externally — the engine's
// EvaluateWithCache returns a slice the engine no longer owns, so
// there is no internal lock here. doctor's single-shot CLI runs Apply
// on the main goroutine before report.Render, which is the supported
// pattern.
package waivers
