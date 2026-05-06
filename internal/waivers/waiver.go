package waivers

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	yaml "go.yaml.in/yaml/v3"

	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/findings"
)

// DefaultFileName is the operator-config waivers file looked up
// alongside the working directory and the user config dir when no
// explicit --waivers flag is given.
const DefaultFileName = ".esops-doctor.yaml"

// Waiver is one rule-level suppression. RuleID is the literal rule id
// (deprecated_aliases are not auto-resolved at this layer; an operator
// referencing an alias gets a no-match, which is the safer default).
//
// Justification is required at load time — a waiver without one is a
// schema error. ExpiresAt is optional; a YYYY-MM-DD date interpreted as
// end-of-day UTC. The chosen-date semantics keep waivers human-friendly
// (no fiddly RFC3339 strings) while still giving "expired today" a
// well-defined moment.
type Waiver struct {
	RuleID        string `yaml:"rule_id"`
	Justification string `yaml:"justification"`
	ExpiresAt     string `yaml:"expires_at"`

	expiresAt *time.Time `yaml:"-"`
}

// File is the on-disk shape of an operator's waivers config. Top-level
// `waivers:` sequence so adding sibling fields (per-cluster groupings,
// labels) doesn't have to break the wire format.
type File struct {
	Waivers []Waiver `yaml:"waivers"`
}

// Set is the loaded, indexed view used at scan time. Keyed by rule_id
// so Apply is O(rules) regardless of waiver count. Multiple waivers
// for the same rule_id collapse to the one defined last in the file —
// duplicates surface as a load-time validation error.
type Set struct {
	byRuleID map[string]Waiver
	source   string
}

// Source returns the file path the set was loaded from. Empty when the
// set was constructed in memory (tests).
func (s *Set) Source() string { return s.source }

// Empty reports whether the set has no waivers. Used by the cli to skip
// the "applied N waivers" log line when nothing was loaded.
func (s *Set) Empty() bool { return s == nil || len(s.byRuleID) == 0 }

// Load reads and validates the waivers file at path. Returns a Set
// even when the file is empty (zero waivers is a valid state — the
// loud-on-expired story still needs a Set to walk).
//
// Validation:
//   - rule_id required
//   - justification required — undocumented suppressions defeat the
//     whole point
//   - expires_at, when present, parses as YYYY-MM-DD
//   - duplicate rule_ids rejected
func Load(path string) (*Set, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- caller-supplied via --waivers
	if err != nil {
		return nil, fmt.Errorf("waivers file %q: %w", path, err)
	}
	return parse(data, path)
}

// LoadDefault searches the documented default locations in order and
// loads the first that exists: ./.esops-doctor.yaml, then
// $XDG_CONFIG_HOME/esops-doctor/waivers.yaml, then
// ~/.config/esops-doctor/waivers.yaml. Returns (nil, nil) when no
// file is found — "no waivers" is a valid scan state, not an error.
func LoadDefault() (*Set, error) {
	for _, p := range defaultSearchPaths() {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return Load(p)
		}
	}
	return nil, nil
}

// defaultSearchPaths returns the ordered list of paths LoadDefault
// considers. Hoisted out of LoadDefault so tests can swap HOME /
// XDG_CONFIG_HOME via env vars and observe the resolved order.
func defaultSearchPaths() []string {
	paths := []string{filepath.Join(".", DefaultFileName)}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		paths = append(paths, filepath.Join(xdg, "esops-doctor", "waivers.yaml"))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths, filepath.Join(home, ".config", "esops-doctor", "waivers.yaml"))
	}
	return paths
}

func parse(data []byte, source string) (*Set, error) {
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", source, err)
	}

	set := &Set{byRuleID: map[string]Waiver{}, source: source}
	var problems []string
	for i, w := range f.Waivers {
		w.RuleID = strings.TrimSpace(w.RuleID)
		w.Justification = strings.TrimSpace(w.Justification)
		w.ExpiresAt = strings.TrimSpace(w.ExpiresAt)

		idx := fmt.Sprintf("waivers[%d]", i)
		if w.RuleID == "" {
			problems = append(problems, fmt.Sprintf("%s: rule_id is required", idx))
			continue
		}
		if w.Justification == "" {
			problems = append(problems, fmt.Sprintf("%s (%s): justification is required",
				idx, w.RuleID))
			continue
		}
		if w.ExpiresAt != "" {
			t, err := parseExpiresAt(w.ExpiresAt)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s (%s): %s", idx, w.RuleID, err))
				continue
			}
			w.expiresAt = &t
		}
		if _, dup := set.byRuleID[w.RuleID]; dup {
			problems = append(problems, fmt.Sprintf("%s (%s): duplicate waiver for rule",
				idx, w.RuleID))
			continue
		}
		set.byRuleID[w.RuleID] = w
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("invalid waivers in %s:\n  %s",
			source, strings.Join(problems, "\n  "))
	}
	return set, nil
}

// parseExpiresAt accepts YYYY-MM-DD and snaps it to end-of-day UTC.
// End-of-day rather than start-of-day so a waiver dated 2026-12-31 is
// active throughout that day on every timezone, matching how a human
// reads "expires Dec 31".
func parseExpiresAt(s string) (time.Time, error) {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("expires_at %q: want YYYY-MM-DD", s)
	}
	return t.Add(24*time.Hour - time.Nanosecond).UTC(), nil
}

// Apply walks results and, for every fail with a matching waiver,
// attaches a Suppression to the Finding. now is the comparison clock
// for ExpiresAt — passed in (rather than read from time.Now) so tests
// can drive the expired branch deterministically.
//
// Active suppressions: Finding.Suppression.Expired = false. The report
// layer skips these when computing severity totals and the --fail-on
// gate so the operator's documented exception clears the build.
//
// Expired suppressions: Finding.Suppression.Expired = true. The
// report layer still counts these toward fail-on so the failure
// re-surfaces, and the message is prefixed with "[waiver expired …]"
// so the operator sees both the original problem and the rotted
// waiver in the same row.
func (s *Set) Apply(now time.Time, results []engine.RuleResult) {
	if s.Empty() {
		return
	}
	for i := range results {
		r := &results[i]
		if r.Status != engine.RuleStatusFail || r.Finding == nil {
			continue
		}
		w, ok := s.byRuleID[r.RuleID]
		if !ok {
			continue
		}
		sup := &findings.Suppression{
			Justification: w.Justification,
			Source:        s.source,
		}
		if w.expiresAt != nil {
			exp := *w.expiresAt
			sup.ExpiresAt = &exp
			if now.After(exp) {
				sup.Expired = true
				r.Finding.Message = expiredPrefix(exp) + r.Finding.Message
			}
		}
		r.Finding.Suppression = sup
	}
}

func expiredPrefix(exp time.Time) string {
	return fmt.Sprintf("[waiver expired %s] ", exp.UTC().Format("2006-01-02"))
}

// ResolveAliases extends the set so a waiver keyed by a rule's
// deprecated_alias also matches the canonical id, and vice versa. The
// aliases map is `alias → canonical`; callers (the cli) build it from
// the rule catalog.
//
// Resolved entries are reported via the resolved callback so the cli
// can debug-log the drift — operators who waive by an alias should
// know their reference is one rename away from breaking. Returns the
// number of entries that were rewritten.
//
// Calling with a nil or empty aliases map is a no-op. Calling with a
// nil callback skips logging but still rewrites; useful in tests.
func (s *Set) ResolveAliases(aliases map[string]string, resolved func(alias, canonical string)) int {
	if s.Empty() || len(aliases) == 0 {
		return 0
	}
	n := 0
	for alias, canonical := range aliases {
		if alias == canonical {
			continue
		}
		w, ok := s.byRuleID[alias]
		if !ok {
			continue
		}
		// If the canonical id already has a waiver the operator
		// authored it explicitly — keep it and drop the alias copy
		// so the explicit one wins.
		if _, exists := s.byRuleID[canonical]; !exists {
			s.byRuleID[canonical] = w
		}
		delete(s.byRuleID, alias)
		if resolved != nil {
			resolved(alias, canonical)
		}
		n++
	}
	return n
}

// AppliedCount returns how many of results have a non-nil Suppression
// (active or expired). Used by the cli to log "applied N waivers"
// without re-walking results in the caller.
func AppliedCount(results []engine.RuleResult) int {
	n := 0
	for _, r := range results {
		if r.Finding != nil && r.Finding.Suppression != nil {
			n++
		}
	}
	return n
}
