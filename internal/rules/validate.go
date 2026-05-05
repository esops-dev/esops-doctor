package rules

import (
	"fmt"
	"net/url"
	"regexp"

	"github.com/esops-dev/esops-doctor/internal/findings"
)

// ValidationError describes a single schema violation. Source is the
// file the rule was loaded from; RuleID is empty when the rule failed
// before an ID could be parsed.
type ValidationError struct {
	Source  string
	RuleID  string
	Message string
}

func (e ValidationError) Error() string {
	switch {
	case e.RuleID == "" && e.Source == "":
		return e.Message
	case e.RuleID == "":
		return fmt.Sprintf("%s: %s", e.Source, e.Message)
	default:
		return fmt.Sprintf("%s: rule %q: %s", e.Source, e.RuleID, e.Message)
	}
}

// ruleIDPattern is the canonical form for rule IDs: lowercase letter
// start, then lowercase letters / digits / underscores. Operator
// waivers reference these IDs verbatim, so the pattern is intentionally
// narrow — case variations or punctuation would create silent waiver
// mismatches.
var ruleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

var (
	validDialects = map[string]struct{}{
		"elasticsearch": {},
		"opensearch":    {},
	}
	validEffort = map[string]struct{}{
		"":       {},
		"low":    {},
		"medium": {},
		"high":   {},
	}
)

// Validate runs schema checks on the catalog and returns the list of
// violations. Empty slice means the catalog is well-formed.
//
// What this layer checks:
//   - required fields present (id, name, category, severity, description,
//     probe, condition, message, dialects)
//   - id and deprecated_aliases match the canonical pattern
//   - severity is a known level (the YAML unmarshaller already enforces
//     this, but rules constructed in code path through here too)
//   - dialects is non-empty and each entry is recognised
//   - effort, when set, is one of the documented values
//   - remediation.doc_url, when set, parses as a URL
//   - id and alias namespaces are unique across the catalog
//
// What this layer does NOT check (deferred):
//   - CEL expression compilation — owned by the engine package
//   - probe-name resolution against a registered probe — owned by the
//     probe package
//
// Both deferred checks land when their owning packages exist; gating
// validate-rules on packages that don't exist yet would force premature
// commitment to interfaces.
func (c *Catalog) Validate() []ValidationError {
	var errs []ValidationError
	seen := make(map[string]string) // id (or alias) → source where it was first seen

	for _, r := range c.Rules {
		errs = append(errs, validateRule(r)...)

		if r.ID != "" {
			if prev, ok := seen[r.ID]; ok {
				errs = append(errs, ValidationError{
					Source:  r.Source,
					RuleID:  r.ID,
					Message: fmt.Sprintf("duplicate id (also defined in %s)", prev),
				})
			} else {
				seen[r.ID] = r.Source
			}
		}
		for _, alias := range r.DeprecatedAliases {
			if alias == "" {
				continue
			}
			if prev, ok := seen[alias]; ok {
				errs = append(errs, ValidationError{
					Source:  r.Source,
					RuleID:  r.ID,
					Message: fmt.Sprintf("deprecated_alias %q collides with id from %s", alias, prev),
				})
			} else {
				seen[alias] = r.Source
			}
		}
	}
	return errs
}

func validateRule(r Rule) []ValidationError {
	var errs []ValidationError
	add := func(msg string) {
		errs = append(errs, ValidationError{Source: r.Source, RuleID: r.ID, Message: msg})
	}

	if r.ID == "" {
		errs = append(errs, ValidationError{Source: r.Source, Message: "id is required"})
	} else if !ruleIDPattern.MatchString(r.ID) {
		add("id must match ^[a-z][a-z0-9_]*$")
	}
	if r.Name == "" {
		add("name is required")
	}
	if r.Category == "" {
		add("category is required")
	}
	if r.Severity == findings.SeverityUnknown {
		add("severity is required (info, warn, error, critical)")
	}
	if r.Description == "" {
		add("description is required")
	}
	if r.Probe == "" {
		add("probe is required")
	}
	if r.Condition == "" {
		add("condition is required")
	}
	if r.Message == "" {
		add("message is required")
	}

	if len(r.Dialects) == 0 {
		add("dialects must list at least one of: elasticsearch, opensearch")
	}
	for _, d := range r.Dialects {
		if _, ok := validDialects[d]; !ok {
			add(fmt.Sprintf("unknown dialect %q (want: elasticsearch, opensearch)", d))
		}
	}

	if _, ok := validEffort[r.Effort]; !ok {
		add(fmt.Sprintf("unknown effort %q (want: low, medium, high)", r.Effort))
	}

	if u := r.Remediation.DocURL; u != "" {
		if _, err := url.Parse(u); err != nil {
			add(fmt.Sprintf("invalid remediation doc_url: %s", err))
		}
	}

	for _, alias := range r.DeprecatedAliases {
		if alias == "" {
			add("deprecated_aliases entries must be non-empty")
			continue
		}
		if !ruleIDPattern.MatchString(alias) {
			add(fmt.Sprintf("deprecated_alias %q must match ^[a-z][a-z0-9_]*$", alias))
		}
	}

	return errs
}
