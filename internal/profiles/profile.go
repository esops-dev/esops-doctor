package profiles

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	esopsdoctor "github.com/esops-dev/esops-doctor"
	"github.com/esops-dev/esops-doctor/internal/findings"
	"github.com/esops-dev/esops-doctor/internal/rules"
)

// Profile is one named scan configuration. Empty slices mean "no
// constraint" (every rule passes the filter); a populated IncludeTags
// or RuleIDs narrows the run to matches.
//
// Selection precedence is union semantics: a rule survives the filter
// if (RuleIDs is empty OR rule.ID is in RuleIDs) AND (IncludeTags is
// empty OR rule has at least one matching tag) AND (no rule tag is in
// SkipTags). SkipTags wins over IncludeTags so a profile can subtract
// from a tag-narrowed selection.
type Profile struct {
	Name              string                       `yaml:"name"`
	Description       string                       `yaml:"description"`
	SeverityOverrides map[string]findings.Severity `yaml:"severity_overrides"`
	SkipTags          []string                     `yaml:"skip_tags"`
	IncludeTags       []string                     `yaml:"include_tags"`
	RuleIDs           []string                     `yaml:"rule_ids"`

	Source string `yaml:"-"`
}

// Catalog is the loaded set of profiles, keyed by name. Built once at
// CLI startup; never mutated after Load.
type Catalog struct {
	profiles map[string]*Profile
}

// Names returns the profile names in deterministic order. Used by the
// scan command to list available profiles in usage errors so a typo
// like --profile=prdo gets a useful suggestion list.
func (c *Catalog) Names() []string {
	out := make([]string, 0, len(c.profiles))
	for n := range c.profiles {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Get returns the profile by name. The error is the friendly usage
// message — caller wraps it with exit.Usage to map to exit 2.
func (c *Catalog) Get(name string) (*Profile, error) {
	p, ok := c.profiles[name]
	if !ok {
		return nil, fmt.Errorf("unknown profile %q (available: %s)",
			name, strings.Join(c.Names(), ", "))
	}
	return p, nil
}

// LoadEmbedded loads the profiles baked into the binary at build time.
// This is the v0.1 default; layered overrides (--profiles-dir,
// $XDG_CONFIG_HOME) are deferred to a later milestone.
func LoadEmbedded() (*Catalog, error) {
	return LoadFS(esopsdoctor.Profiles, "profiles")
}

// LoadFS walks fsys under root for *.yaml files and parses each into a
// Profile. The walk skips directories and non-YAML files so dotfile
// placeholders are silently fine.
func LoadFS(fsys fs.FS, root string) (*Catalog, error) {
	cat := &Catalog{profiles: map[string]*Profile{}}
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return nil
		}
		data, rerr := fs.ReadFile(fsys, p)
		if rerr != nil {
			return fmt.Errorf("reading %s: %w", p, rerr)
		}
		var prof Profile
		if uerr := yaml.Unmarshal(data, &prof); uerr != nil {
			return fmt.Errorf("parsing %s: %w", p, uerr)
		}
		prof.Source = p
		if prof.Name == "" {
			// Fall back to the file stem so an unnamed profile still
			// surfaces with a useful identifier in error messages
			// rather than the empty key collision below.
			prof.Name = strings.TrimSuffix(path.Base(p), ".yaml")
		}
		if existing, ok := cat.profiles[prof.Name]; ok {
			return fmt.Errorf("duplicate profile %q in %s (also defined in %s)",
				prof.Name, p, existing.Source)
		}
		cat.profiles[prof.Name] = &prof
		return nil
	})
	if err != nil {
		return nil, err
	}
	return cat, nil
}

// UnknownSeverityOverrides returns the rule IDs in p.SeverityOverrides
// that don't appear in cat. An empty result means every override
// references a real rule. Used by the cli to emit a warn log so an
// operator typo (`severity_overrides: {hep_size: critical}`) doesn't
// silently no-op for the rest of a scan's life.
//
// Sorted for deterministic log output.
func (p *Profile) UnknownSeverityOverrides(cat *rules.Catalog) []string {
	if p == nil || len(p.SeverityOverrides) == 0 {
		return nil
	}
	known := make(map[string]struct{}, len(cat.Rules))
	for _, r := range cat.Rules {
		known[r.ID] = struct{}{}
		for _, alias := range r.DeprecatedAliases {
			known[alias] = struct{}{}
		}
	}
	var unknown []string
	for id := range p.SeverityOverrides {
		if _, ok := known[id]; !ok {
			unknown = append(unknown, id)
		}
	}
	sort.Strings(unknown)
	return unknown
}

// Apply returns a copy of cat filtered and severity-adjusted by p.
// Rules that don't match the selection are dropped from the returned
// catalog so the engine doesn't compile or evaluate them. SeverityOverrides
// rewrites the severity in-place on the surviving copies — the engine
// reads rule.Severity at finding-construction time, so the override
// flows into the produced Finding.Severity without engine awareness of
// profiles.
//
// The input catalog is not mutated; callers can hold a single embedded
// catalog and apply different profiles per-scan.
func (p *Profile) Apply(cat *rules.Catalog) *rules.Catalog {
	if p == nil || cat == nil {
		return cat
	}
	allowID := setOf(p.RuleIDs)
	includeTag := setOf(p.IncludeTags)
	skipTag := setOf(p.SkipTags)

	out := &rules.Catalog{}
	for _, r := range cat.Rules {
		if !ruleMatches(r, allowID, includeTag, skipTag) {
			continue
		}
		copyRule := r
		if sev, ok := p.SeverityOverrides[r.ID]; ok && sev != findings.SeverityUnknown {
			copyRule.Severity = sev
		}
		out.Rules = append(out.Rules, copyRule)
	}
	return out
}

func ruleMatches(r rules.Rule, allowID, includeTag, skipTag map[string]struct{}) bool {
	if len(allowID) > 0 {
		if _, ok := allowID[r.ID]; !ok {
			return false
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
		out[x] = struct{}{}
	}
	return out
}
