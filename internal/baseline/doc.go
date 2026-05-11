// Package baseline parses a previous scan report (SARIF or JSON) and
// matches its findings against the current run so a CI gate can adopt
// doctor on a brownfield cluster without "fix everything in one go".
//
// The match key is a finding fingerprint: (rule_id, dialect, target).
// Today every finding the engine produces is cluster-wide — one rule,
// one dialect, no per-target sub-finding — so target is empty and the
// effective key is (rule_id, dialect). The target slot is reserved on
// the wire so a future rule that emits per-node / per-index findings
// can extend the schema additively without breaking existing
// baselines.
//
// Two formats are accepted as inputs:
//
//   - SARIF 2.1.0 (lingua franca): each result row's partialFingerprints
//     carries the canonical key. Older SARIF files written before doctor
//     emitted partialFingerprints still load — the loader falls back to
//     ruleId and synthesises the dialect from the run-level driver
//     properties when present.
//   - Doctor JSON Document (schema_version 1): Cluster.Dialect plus each
//     failing Result.RuleID round-trips without extra plumbing.
//
// Anything not a recognised SARIF or Document JSON file is rejected at
// load time so a typo'd --baseline path doesn't silently match nothing.
package baseline
