package findings

import (
	"fmt"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// Severity ranks findings on a four-level ladder. SeverityUnknown is
// the zero value and is reserved for "not yet parsed" — a loader that
// produces it should reject the rule. The ordering is meaningful:
// info < warn < error < critical, used by --fail-on to decide whether a
// scan exits 20.
type Severity int

// Severity levels in increasing order of urgency. SeverityUnknown is
// the zero value and indicates "not parsed"; loaders reject it.
const (
	SeverityUnknown Severity = iota
	SeverityInfo
	SeverityWarn
	SeverityError
	SeverityCritical
)

// Rank returns the integer urgency of s — higher is more urgent. Used
// by renderers that need to order findings by severity (HTML's
// sortable column, future sort keys for json/yaml). The value is the
// raw iota position, kept stable; new severities should land at the
// existing edges (zero or above critical) rather than between
// existing ones, or downstream sort orders will silently shift.
func (s Severity) Rank() int { return int(s) }

// String returns the canonical lowercase rendering. SeverityUnknown
// renders as "" so a missing-severity loading failure surfaces visibly
// in error messages rather than silently looking valid.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarn:
		return "warn"
	case SeverityError:
		return "error"
	case SeverityCritical:
		return "critical"
	default:
		return ""
	}
}

// ParseSeverity is case-insensitive and accepts "warning" as an alias
// for "warn" — slog already normalises that pair, and human-edited
// config files routinely use either form.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return SeverityInfo, nil
	case "warn", "warning":
		return SeverityWarn, nil
	case "error":
		return SeverityError, nil
	case "critical":
		return SeverityCritical, nil
	default:
		return SeverityUnknown, fmt.Errorf("unknown severity %q (want: info, warn, error, critical)", s)
	}
}

// MarshalYAML emits the canonical string form so generated rule files
// match hand-written ones byte-for-byte.
func (s Severity) MarshalYAML() (interface{}, error) {
	str := s.String()
	if str == "" {
		return nil, fmt.Errorf("cannot marshal SeverityUnknown")
	}
	return str, nil
}

// UnmarshalYAML accepts a scalar string. Sequences and mappings are a
// hard error so a typo like `severity: [critical]` doesn't silently
// resolve to SeverityUnknown.
func (s *Severity) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("severity at line %d must be a string", node.Line)
	}
	parsed, err := ParseSeverity(node.Value)
	if err != nil {
		return fmt.Errorf("severity at line %d: %w", node.Line, err)
	}
	*s = parsed
	return nil
}
