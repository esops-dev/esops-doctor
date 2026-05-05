package findings

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
}

// Remediation describes how to fix a finding. Where one applies,
// Command is the concrete `esops` invocation that fixes the underlying
// condition; DocURL points at upstream documentation.
type Remediation struct {
	Command string `yaml:"command"`
	DocURL  string `yaml:"doc_url"`
}
