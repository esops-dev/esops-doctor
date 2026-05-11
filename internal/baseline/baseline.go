package baseline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/esops-dev/esops-doctor/internal/findings"
)

// SchemaVersion is the wire-format version of the (rule_id, dialect,
// target) fingerprint contract. Bumped only when the fingerprint
// itself changes meaning; adding new optional fields to baseline files
// is additive and does not bump it. Operators pinning to
// schema_version=1 can rely on (rule_id, dialect, target) being a
// stable identity.
const SchemaVersion = 1

// Fingerprint is the stable identity of a finding across scans. It is
// the documented match key: a baseline entry and a current finding
// match iff their Fingerprints are equal.
//
// Target is reserved for the future. Today every doctor finding is
// cluster-wide so the field is always empty; the slot is part of the
// schema 1 contract so a per-target rule can populate it later
// without breaking baselines authored against the cluster-wide form.
type Fingerprint struct {
	RuleID  string `json:"rule_id"`
	Dialect string `json:"dialect"`
	Target  string `json:"target,omitempty"`
}

// Key returns the canonical map-index form of the fingerprint. The
// pipe character is reserved in none of (rule_id, dialect, target),
// so the form is unambiguous.
func (f Fingerprint) Key() string {
	return f.RuleID + "|" + f.Dialect + "|" + f.Target
}

// String returns a human-readable form for log lines and error
// messages. The empty-target form omits the trailing pipe.
func (f Fingerprint) String() string {
	if f.Target == "" {
		return fmt.Sprintf("%s/%s", f.RuleID, f.Dialect)
	}
	return fmt.Sprintf("%s/%s/%s", f.RuleID, f.Dialect, f.Target)
}

// Entry is one row in a baseline file: a fingerprint plus the
// severity and message captured at the time the baseline was written.
// Severity and Message are advisory — the match key is the
// fingerprint alone — but diff uses them to report
// severity-changed findings.
type Entry struct {
	Fingerprint Fingerprint
	Severity    findings.Severity
	Message     string
}

// Set is the loaded, indexed view of a baseline file. Keyed by
// Fingerprint.Key() so Apply is O(rules) regardless of baseline size.
// Source is the file path the set was loaded from; Apply propagates
// it onto findings.BaselineMatch.Source for reporting.
type Set struct {
	entries map[string]Entry
	source  string
	format  string
}

// Source returns the file path the set was loaded from. Empty when
// the set was constructed in memory (tests).
func (s *Set) Source() string {
	if s == nil {
		return ""
	}
	return s.source
}

// Format returns the parsed file's format ("sarif" or "json"). Used
// by log lines so an operator can confirm doctor read what they
// thought they passed.
func (s *Set) Format() string {
	if s == nil {
		return ""
	}
	return s.format
}

// Empty reports whether the set carries no entries. A nil receiver is
// empty.
func (s *Set) Empty() bool { return s == nil || len(s.entries) == 0 }

// Len returns the number of fingerprints in the set.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.entries)
}

// Entries returns the indexed entries in unspecified order. Callers
// that need a stable order should sort by Fingerprint.Key().
func (s *Set) Entries() []Entry {
	if s == nil {
		return nil
	}
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e)
	}
	return out
}

// Contains reports whether the set has an entry matching the
// fingerprint. Used by diff to compute set differences.
func (s *Set) Contains(fp Fingerprint) bool {
	if s == nil {
		return false
	}
	_, ok := s.entries[fp.Key()]
	return ok
}

// Get returns the entry whose fingerprint matches, plus whether one
// was found. Useful for severity-changed diffs where the caller needs
// the baseline severity alongside the boolean.
func (s *Set) Get(fp Fingerprint) (Entry, bool) {
	if s == nil {
		return Entry{}, false
	}
	e, ok := s.entries[fp.Key()]
	return e, ok
}

// NewSet builds a Set from a slice of entries. Duplicate fingerprints
// collapse to the entry defined last in the slice — same convention
// as the waiver loader.
func NewSet(entries []Entry, source, format string) *Set {
	s := &Set{
		entries: make(map[string]Entry, len(entries)),
		source:  source,
		format:  format,
	}
	for _, e := range entries {
		s.entries[e.Fingerprint.Key()] = e
	}
	return s
}

// Load reads the baseline file at path and parses it as either SARIF
// or doctor JSON. Format is auto-detected from the file contents — a
// SARIF doc carries a "$schema" key referencing the SARIF schema, a
// doctor JSON doc carries a top-level "schema_version" and "tool"
// key. The extension is consulted only as a tiebreaker.
//
// An empty or unrecognised file is a load-time error: a typo'd
// --baseline path should not silently match nothing.
func Load(path string) (*Set, error) {
	if path == "" {
		return nil, fmt.Errorf("baseline file path is empty")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- caller-supplied via --baseline
	if err != nil {
		return nil, fmt.Errorf("baseline file %q: %w", path, err)
	}
	format, err := detectFormat(data, path)
	if err != nil {
		return nil, fmt.Errorf("baseline file %q: %w", path, err)
	}
	switch format {
	case "sarif":
		return parseSARIF(data, path)
	case "json":
		return parseJSON(data, path)
	default:
		return nil, fmt.Errorf("baseline file %q: unrecognised format", path)
	}
}

// detectFormat sniffs the raw bytes to pick a parser. The order is
// SARIF (look for a $schema field naming the SARIF schema) before
// doctor JSON (schema_version + tool); a SARIF file written by a
// downstream that also carries "schema_version" loads as SARIF
// because the $schema string is the harder identifier to fake.
//
// The extension hint is consulted only when the contents are
// ambiguous — keeps operators who name their file "baseline.txt" or
// pipe SARIF through `cat` honest, while not over-trusting an
// extension that doesn't match the bytes.
func detectFormat(data []byte, path string) (string, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return "", fmt.Errorf("baseline file is empty")
	}
	if trimmed[0] != '{' {
		return "", fmt.Errorf("baseline must be a JSON object")
	}
	// Probe just enough of the top level to distinguish formats.
	var probe struct {
		Schema        string `json:"$schema"`
		Version       string `json:"version"`
		SchemaVersion *int   `json:"schema_version"`
		Tool          *struct {
			Name string `json:"name"`
		} `json:"tool"`
		Runs []json.RawMessage `json:"runs"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", fmt.Errorf("parsing JSON: %w", err)
	}
	switch {
	case strings.Contains(probe.Schema, "sarif"):
		return "sarif", nil
	case len(probe.Runs) > 0 && probe.Version != "":
		// SARIF without a $schema but with runs[] and version is still
		// recognisably SARIF.
		return "sarif", nil
	case probe.SchemaVersion != nil && probe.Tool != nil:
		return "json", nil
	}
	// Last resort: extension hint.
	switch strings.ToLower(extOf(path)) {
	case ".sarif":
		return "sarif", nil
	case ".json":
		// A bare doctor-shaped JSON with neither schema_version nor
		// tool is too ambiguous to accept as a baseline.
		return "", fmt.Errorf("not a doctor JSON document (missing schema_version + tool)")
	}
	return "", fmt.Errorf("could not determine format from contents or extension")
}

// extOf returns the lowercased extension including the leading dot,
// or "" when path has none.
func extOf(path string) string {
	i := strings.LastIndex(path, ".")
	if i < 0 {
		return ""
	}
	return path[i:]
}
