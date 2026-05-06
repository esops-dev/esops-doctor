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
}

// Remediation describes how to fix a finding. Where one applies,
// Command is the concrete `esops` invocation that fixes the underlying
// condition; DocURL points at upstream documentation.
type Remediation struct {
	Command string `yaml:"command" json:"command,omitempty"`
	DocURL  string `yaml:"doc_url" json:"doc_url,omitempty"`
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
