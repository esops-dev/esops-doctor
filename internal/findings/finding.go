package findings

import "time"

// Finding is the produced result of evaluating a rule against probe
// data. Engine populates these; report layers consume them. The shape
// is deliberately minimal — fields will grow when the engine and
// waivers packages land.
type Finding struct {
	RuleID      string
	Name        string
	Severity    Severity
	Category    string
	Message     string
	Remediation Remediation
	Dialect     string

	// Suppression is non-nil when a waiver matched this finding. An
	// active (non-expired) waiver tells the report layer to skip this
	// finding when computing the --fail-on threshold; an expired one
	// keeps the failure live and surfaces "waiver expired" so the
	// suppression cannot rot silently.
	Suppression *Suppression

	// Baseline is non-nil when this finding matched an entry in the
	// operator-supplied baseline (--baseline PATH). The fail-on gate
	// skips matched findings so a CI gate adopting doctor on a
	// brownfield cluster only fails on findings that did not appear
	// in the baseline. The finding stays in the report.
	Baseline *BaselineMatch
}

// BaselineMatch records that a finding was present in the baseline
// passed via --baseline. Source is the baseline file the match came
// from; renderers surface it so the operator can trace why a finding
// was treated as preexisting.
type BaselineMatch struct {
	Source string `json:"source,omitempty" yaml:"source,omitempty"`
}

// Remediation describes how to fix a finding. Command is a free-text
// instruction (often a curl invocation or a checklist), DocURL points
// at upstream documentation, and EsopsCommands lists concrete `esops`
// subcommands that surface the same data or apply a fix — these let an
// operator triage a finding directly with the imperative tool.
type Remediation struct {
	Command       string   `yaml:"command" json:"command,omitempty"`
	DocURL        string   `yaml:"doc_url" json:"doc_url,omitempty"`
	EsopsCommands []string `yaml:"esops_commands,omitempty" json:"esops_commands,omitempty"`
}

// Suppression is the waiver attached to a finding. Justification is
// always populated (waivers without a justification are rejected at
// load time). ExpiresAt is the parsed YYYY-MM-DD; the zero value means
// "no expiry". Expired is the load-time evaluation of ExpiresAt against
// the scan clock — kept as a bool rather than recomputed by callers so
// the report and exit-code paths agree on a single decision.
type Suppression struct {
	Justification string     `json:"justification" yaml:"justification"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	Expired       bool       `json:"expired" yaml:"expired"`
	Source        string     `json:"source,omitempty" yaml:"source,omitempty"`
}
