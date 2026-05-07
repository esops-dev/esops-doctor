package report

import (
	"time"

	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/findings"
)

// SchemaVersion is the wire-format version of the structured report
// emitted by the json and yaml renderers. Bumped only for
// downstream-breaking changes; additive fields don't bump it. A
// downstream that pins to schema_version=1 should keep working until
// the next bump.
const SchemaVersion = 1

// Document is the JSON/YAML wire shape. It is also the intermediate
// model the sarif/junit/html renderers consume so every format
// agrees on what a "result" looks like.
type Document struct {
	SchemaVersion int      `json:"schema_version" yaml:"schema_version"`
	Tool          Tool     `json:"tool" yaml:"tool"`
	Cluster       Cluster  `json:"cluster" yaml:"cluster"`
	Scan          Scan     `json:"scan" yaml:"scan"`
	Summary       Summary  `json:"summary" yaml:"summary"`
	Results       []Result `json:"results,omitempty" yaml:"results,omitempty"`
}

// Tool identifies the binary that produced the report. Useful for
// downstream tools that ingest reports from a fleet — knowing the
// doctor and esops-go module version lets a triage flow attribute a
// finding to a specific build. Commit and EsopsModule are populated
// at link time via -ldflags; in dev builds they read "none" /
// "unknown" and surface that way to the wire.
type Tool struct {
	Name        string `json:"name" yaml:"name"`
	Version     string `json:"version" yaml:"version"`
	Commit      string `json:"commit,omitempty" yaml:"commit,omitempty"`
	EsopsModule string `json:"esops_module,omitempty" yaml:"esops_module,omitempty"`
}

// Cluster identifies the target the scan ran against. Name and Version
// are best-effort — pkg/cluster fills them when GET / returns them, and
// they're omitted from output when empty so a partial response doesn't
// produce noisy `name: ""` rows.
//
// Health, NodeCount, and DataNodeCount are sourced from the
// cluster_health probe before the engine runs. They're cheap (one
// API call) and put a passing-rules report into context — "1 rule
// passed" is more meaningful when the reader knows the cluster is
// green with three nodes than just a bare green tick.
type Cluster struct {
	Name          string `json:"name,omitempty" yaml:"name,omitempty"`
	Dialect       string `json:"dialect" yaml:"dialect"`
	Version       string `json:"version,omitempty" yaml:"version,omitempty"`
	Health        string `json:"health,omitempty" yaml:"health,omitempty"`
	NodeCount     int    `json:"node_count,omitempty" yaml:"node_count,omitempty"`
	DataNodeCount int    `json:"data_node_count,omitempty" yaml:"data_node_count,omitempty"`
}

// Scan carries metadata about the scan run itself. StartedAt is RFC3339
// UTC so a downstream that tails reports has a stable key for
// chronological ordering. DurationMs is the engine wall-clock;
// RuleCount is the total rules considered (passes, fails, skips, and
// errors).
type Scan struct {
	StartedAt  string `json:"started_at,omitempty" yaml:"started_at,omitempty"`
	DurationMs int64  `json:"duration_ms" yaml:"duration_ms"`
	RuleCount  int    `json:"rule_count" yaml:"rule_count"`
}

// Summary is the per-status / per-severity tally surfaced alongside
// the full results list. Mirrors the table renderer's footer counts so
// the same numbers appear regardless of format. Waived counts the
// active-waiver findings excluded from BySeverity / Failed; expired
// waivers fall back into Failed and BySeverity because the suppression
// failed and the finding fires loud.
type Summary struct {
	Passed     int            `json:"passed" yaml:"passed"`
	Failed     int            `json:"failed" yaml:"failed"`
	Skipped    int            `json:"skipped" yaml:"skipped"`
	Errored    int            `json:"errored" yaml:"errored"`
	Waived     int            `json:"waived" yaml:"waived"`
	BySeverity SeverityCounts `json:"by_severity" yaml:"by_severity"`
}

// SeverityCounts is the failing-finding tally by severity. The four
// fields are always emitted (no omitempty) so downstream parsers can
// rely on the keys being present.
type SeverityCounts struct {
	Critical int `json:"critical" yaml:"critical"`
	Error    int `json:"error" yaml:"error"`
	Warn     int `json:"warn" yaml:"warn"`
	Info     int `json:"info" yaml:"info"`
}

// Result is one rule's outcome. The rule-metadata fields (Name,
// Category, Severity, Description, Probe, Dialects, Tags) are
// populated for *every* status — so a passing rule still tells a
// reader what it checked and why it matters. Status-specific fields
// (Message, Remediation, SkipReason, Error, Suppression) only
// populate for the status that produces them, kept tidy by
// `omitempty`.
type Result struct {
	RuleID      string                `json:"rule_id" yaml:"rule_id"`
	Name        string                `json:"name,omitempty" yaml:"name,omitempty"`
	Category    string                `json:"category,omitempty" yaml:"category,omitempty"`
	Severity    string                `json:"severity,omitempty" yaml:"severity,omitempty"`
	Description string                `json:"description,omitempty" yaml:"description,omitempty"`
	Probe       string                `json:"probe,omitempty" yaml:"probe,omitempty"`
	Dialects    []string              `json:"dialects,omitempty" yaml:"dialects,omitempty"`
	Tags        []string              `json:"tags,omitempty" yaml:"tags,omitempty"`
	Status      string                `json:"status" yaml:"status"`
	DurationMs  int64                 `json:"duration_ms" yaml:"duration_ms"`
	Message     string                `json:"message,omitempty" yaml:"message,omitempty"`
	Remediation *findings.Remediation `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	SkipReason  string                `json:"skip_reason,omitempty" yaml:"skip_reason,omitempty"`
	Error       string                `json:"error,omitempty" yaml:"error,omitempty"`
	Suppression *findings.Suppression `json:"suppression,omitempty" yaml:"suppression,omitempty"`
}

// BuildDocument converts the engine's per-rule results into the wire
// shape. Honours opts.SummaryOnly (drops Results entirely) and
// opts.Quiet (drops pass and skipped rows; failing and errored rows
// always survive because those are the operator-actionable ones). The
// summary counts always reflect the full result set regardless of
// these flags so downstream parsers see the truth.
func BuildDocument(h Header, results []engine.RuleResult, opts Options) Document {
	doc := Document{
		SchemaVersion: SchemaVersion,
		Tool: Tool{
			Name:        h.ToolName,
			Version:     h.ToolVersion,
			Commit:      h.ToolCommit,
			EsopsModule: h.ToolEsopsModule,
		},
		Cluster: Cluster{
			Name:          h.ClusterName,
			Dialect:       h.Dialect,
			Version:       h.Version,
			Health:        h.Health,
			NodeCount:     h.NodeCount,
			DataNodeCount: h.DataNodeCount,
		},
		Scan: Scan{
			StartedAt:  formatStartedAt(h.StartedAt),
			DurationMs: h.Duration.Milliseconds(),
			RuleCount:  len(results),
		},
		Summary: buildSummary(results),
	}
	if opts.SummaryOnly {
		return doc
	}
	doc.Results = buildResults(results, opts)
	return doc
}

// formatStartedAt renders a wall-clock timestamp as RFC3339 UTC. The
// zero time renders as "" so the field is omitempty-elided when the
// caller hasn't filled it in (legacy tests that build a Header by
// hand without setting StartedAt).
func formatStartedAt(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func buildSummary(results []engine.RuleResult) Summary {
	c := classify(results)
	return Summary{
		Passed:  c.passed,
		Failed:  c.critical + c.error + c.warn + c.info,
		Skipped: c.skipped,
		Errored: c.errored,
		Waived:  c.waived,
		BySeverity: SeverityCounts{
			Critical: c.critical,
			Error:    c.error,
			Warn:     c.warn,
			Info:     c.info,
		},
	}
}

func buildResults(results []engine.RuleResult, opts Options) []Result {
	out := make([]Result, 0, len(results))
	for _, r := range results {
		if opts.Quiet && (r.Status == engine.RuleStatusPass || r.Status == engine.RuleStatusSkipped) {
			continue
		}
		out = append(out, toResult(r))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// toResult flattens an engine.RuleResult into a Result row.
// Rule-metadata fields read from r.Rule (populated by the engine even
// for passes/skips/errors). Status-specific fields override or
// supplement those — for instance a finding's runtime severity wins
// over the rule's default if they ever diverge (today they don't).
func toResult(r engine.RuleResult) Result {
	out := Result{
		RuleID:      r.RuleID,
		Name:        r.Rule.Name,
		Category:    r.Rule.Category,
		Severity:    r.Rule.Severity.String(),
		Description: r.Rule.Description,
		Probe:       r.Rule.Probe,
		Dialects:    r.Rule.Dialects,
		Tags:        r.Rule.Tags,
		Status:      r.Status.String(),
		DurationMs:  r.Duration.Milliseconds(),
	}
	switch r.Status {
	case engine.RuleStatusFail:
		if r.Finding != nil {
			out.Severity = r.Finding.Severity.String()
			out.Message = r.Finding.Message
			if rem := r.Finding.Remediation; rem.Command != "" || rem.DocURL != "" || len(rem.EsopsCommands) > 0 {
				rcopy := rem
				out.Remediation = &rcopy
			}
			if sup := r.Finding.Suppression; sup != nil {
				scopy := *sup
				out.Suppression = &scopy
			}
		}
	case engine.RuleStatusSkipped:
		out.SkipReason = r.SkipReason
	case engine.RuleStatusError:
		if r.Err != nil {
			out.Error = r.Err.Error()
		}
	}
	return out
}
