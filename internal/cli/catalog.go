package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/esops-dev/esops-doctor/internal/exit"
	"github.com/esops-dev/esops-doctor/internal/probes"
	"github.com/esops-dev/esops-doctor/internal/rules"
)

// loadLayeredCatalog returns the rule catalog every operator-facing
// command runs against: the embedded core, layered with --rules-dir
// (when set) and the user rules.d directory (when present), then
// validated as a whole. The order matches CLAUDE.md §7's documented
// loading order: embedded → --rules-dir → user dir.
//
// Layering is implemented as catalog Append; the validator catches
// duplicate IDs as a hard error so an operator who tried to "override"
// a shipped rule sees the collision rather than silently shadowing it.
// True override-by-ID semantics is a separate piece of work — the
// milestone only requires honouring the directories.
//
// Errors are wrapped with exit.Catalog so the binary maps to exit 21,
// the documented "rule catalog error" code per CLAUDE.md §10.
func loadLayeredCatalog(rulesDir string) (*rules.Catalog, error) {
	cat, err := assembleLayeredCatalog(rulesDir)
	if err != nil {
		return nil, err
	}
	issues := cat.Validate()
	issues = append(issues, cat.ValidateProbes(probes.IsKnown)...)
	if len(issues) > 0 {
		msgs := make([]string, 0, len(issues))
		for _, e := range issues {
			msgs = append(msgs, e.Error())
		}
		return nil, exit.Catalog("rule catalog invalid:\n  %s", strings.Join(msgs, "\n  "))
	}
	return cat, nil
}

// assembleLayeredCatalog builds the layered catalog without validating.
// Split from loadLayeredCatalog so validate-rules can keep its per-issue
// stderr UX (each violation on its own line, distinct from the bundled
// "rule catalog invalid:" message scan/list-rules/explain emit). Both
// callers see the same input: embedded → --rules-dir → user rules.d.
func assembleLayeredCatalog(rulesDir string) (*rules.Catalog, error) {
	cat, err := rules.LoadEmbedded()
	if err != nil {
		return nil, exit.Catalog("loading embedded rules: %s", err)
	}
	if rulesDir != "" {
		extra, err := rules.LoadDir(rulesDir)
		if err != nil {
			return nil, exit.Catalog("%s", err)
		}
		cat.Append(extra)
	}
	if userDir, ok := userRulesDir(); ok {
		extra, err := loadUserRulesDir(userDir)
		if err != nil {
			return nil, err
		}
		if extra != nil {
			cat.Append(extra)
		}
	}
	return cat, nil
}

// loadUserRulesDir reads the user rules.d directory if it exists. A
// missing directory is the common case (most operators don't customise)
// so it returns (nil, nil) silently. A directory that exists but errors
// on read is loud — that's likely a permissions problem an operator
// should know about, not a "no overrides" state.
func loadUserRulesDir(path string) (*rules.Catalog, error) {
	info, err := os.Stat(path) // #nosec G304 -- env-derived user config path
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, exit.Catalog("inspecting user rules dir %q: %s", path, err)
	}
	if !info.IsDir() {
		return nil, nil
	}
	extra, err := rules.LoadDir(path)
	if err != nil {
		return nil, exit.Catalog("%s", err)
	}
	return extra, nil
}

// userRulesDir resolves the user-overrides directory per CLAUDE.md §7:
// `$XDG_CONFIG_HOME/esops-doctor/rules.d/` when XDG is set, otherwise
// `$HOME/.config/esops-doctor/rules.d/`. Returns ok=false only when no
// home can be discovered — extremely rare on a real system, but the
// guard keeps the loader safe under stripped test envs that unset HOME.
func userRulesDir() (string, bool) {
	if x := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); x != "" {
		return filepath.Join(x, "esops-doctor", "rules.d"), true
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", false
	}
	return filepath.Join(home, ".config", "esops-doctor", "rules.d"), true
}

// catalogFilter is the union of --rule-id / --tags / --skip-tags
// selections an operator can apply on top of a profile. Empty fields
// mean "no constraint" — applyCatalogFilter returns the input catalog
// unchanged when every field is empty.
type catalogFilter struct {
	RuleIDs     []string
	IncludeTags []string
	SkipTags    []string
}

// IsEmpty reports whether f imposes any constraint. Used to short-circuit
// catalog allocation when no filtering flag was set.
func (f catalogFilter) IsEmpty() bool {
	return len(f.RuleIDs) == 0 && len(f.IncludeTags) == 0 && len(f.SkipTags) == 0
}

// applyCatalogFilter returns a copy of cat narrowed to rules matching f.
// Selection precedence mirrors profile.Apply: a rule survives when
// (RuleIDs is empty OR id is allowed) AND (IncludeTags is empty OR rule
// has at least one matching tag) AND no rule tag is in SkipTags. The
// input catalog is not mutated.
//
// Unknown rule IDs and tags are returned alongside the filtered
// catalog so the caller can warn — a typo'd `--rule-id heeap_size`
// would otherwise filter the catalog to zero rules silently.
func applyCatalogFilter(cat *rules.Catalog, f catalogFilter) (*rules.Catalog, []string) {
	if cat == nil || f.IsEmpty() {
		return cat, nil
	}
	allowID := setOf(f.RuleIDs)
	includeTag := setOf(f.IncludeTags)
	skipTag := setOf(f.SkipTags)

	known := map[string]struct{}{}
	tagsSeen := map[string]struct{}{}
	for _, r := range cat.Rules {
		known[r.ID] = struct{}{}
		for _, alias := range r.DeprecatedAliases {
			known[alias] = struct{}{}
		}
		for _, t := range r.Tags {
			tagsSeen[t] = struct{}{}
		}
	}

	out := &rules.Catalog{}
	for _, r := range cat.Rules {
		if !filterMatches(r, allowID, includeTag, skipTag) {
			continue
		}
		out.Rules = append(out.Rules, r)
	}

	var unknown []string
	for id := range allowID {
		if _, ok := known[id]; !ok {
			unknown = append(unknown, "rule_id="+id)
		}
	}
	for tag := range includeTag {
		if _, ok := tagsSeen[tag]; !ok {
			unknown = append(unknown, "tag="+tag)
		}
	}
	for tag := range skipTag {
		if _, ok := tagsSeen[tag]; !ok {
			unknown = append(unknown, "skip_tag="+tag)
		}
	}
	return out, unknown
}

func filterMatches(r rules.Rule, allowID, includeTag, skipTag map[string]struct{}) bool {
	if len(allowID) > 0 {
		if _, ok := allowID[r.ID]; !ok {
			matched := false
			for _, alias := range r.DeprecatedAliases {
				if _, ok := allowID[alias]; ok {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}
	if len(includeTag) > 0 {
		matched := false
		for _, t := range r.Tags {
			if _, ok := includeTag[t]; ok {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, t := range r.Tags {
		if _, ok := skipTag[t]; ok {
			return false
		}
	}
	return true
}

func setOf(xs []string) map[string]struct{} {
	if len(xs) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		out[x] = struct{}{}
	}
	return out
}
