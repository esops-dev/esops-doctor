package rules

import (
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	esopsdoctor "github.com/esops-dev/esops-doctor"
	"github.com/esops-dev/esops-doctor/internal/findings"
)

// Rule is one diagnostic check. Field tags match the YAML schema in
// docs/rules.md. Source is set by the loader and is not present in the
// YAML; it is the path the rule was loaded from, used in validation
// error messages so an operator can find the offending file.
//
// CountExpression is an optional CEL expression that returns the number
// substituted into the message's `{{count}}` placeholder when the rule
// fails. When empty, the engine falls back to len(self) — useful as a
// rough total but inaccurate for rules whose Condition aggregates over
// only a subset (e.g. "the *failing* nodes count"). Authors who want
// `{{count}}` to mean "failing items" set CountExpression to the
// matching CEL filter, e.g.
//
//	condition: self.all(n, healthy(n))
//	count_expression: size(self.filter(n, !healthy(n)))
type Rule struct {
	ID                string               `yaml:"id"`
	Name              string               `yaml:"name"`
	Category          string               `yaml:"category"`
	Severity          findings.Severity    `yaml:"severity"`
	Description       string               `yaml:"description"`
	Probe             string               `yaml:"probe"`
	Condition         string               `yaml:"condition"`
	CountExpression   string               `yaml:"count_expression"`
	Message           string               `yaml:"message"`
	Remediation       findings.Remediation `yaml:"remediation"`
	Tags              []string             `yaml:"tags"`
	Dialects          []string             `yaml:"dialects"`
	AffectedVersions  []string             `yaml:"affected_versions"`
	Effort            string               `yaml:"effort"`
	DeprecatedAliases []string             `yaml:"deprecated_aliases"`

	Source string `yaml:"-"`
}

// fileShape is the top-level structure of a rule YAML file. Multiple
// rules per file are allowed so a category can be authored as a single
// document when that reads more naturally.
type fileShape struct {
	Checks []Rule `yaml:"checks"`
}

// Catalog holds a sorted list of loaded rules. Sorting is by ID so the
// output of validate-rules and list-rules is deterministic.
type Catalog struct {
	Rules []Rule
}

// LoadEmbedded loads the rules baked into the binary at build time.
// This is the v0.1 default — operators add catalogs via --rules-dir on
// top of this baseline.
func LoadEmbedded() (*Catalog, error) {
	return LoadFS(esopsdoctor.Catalog, "rules")
}

// LoadFS walks fsys under root for *.yaml files and parses each into a
// Catalog. The walk skips directories and non-YAML files, so dotfile
// placeholders and category subdirectories are silently fine.
func LoadFS(fsys fs.FS, root string) (*Catalog, error) {
	var cat Catalog
	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, rerr := fs.ReadFile(fsys, path)
		if rerr != nil {
			return fmt.Errorf("reading %s: %w", path, rerr)
		}
		var shape fileShape
		if uerr := yaml.Unmarshal(data, &shape); uerr != nil {
			return fmt.Errorf("parsing %s: %w", path, uerr)
		}
		for i := range shape.Checks {
			shape.Checks[i].Source = path
		}
		cat.Rules = append(cat.Rules, shape.Checks...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(cat.Rules, func(i, j int) bool { return cat.Rules[i].ID < cat.Rules[j].ID })
	return &cat, nil
}

// LoadDir is the on-disk equivalent of LoadFS, used by --rules-dir. It
// validates that path is a directory before walking it so a typo
// surfaces with a clear message rather than an empty catalog.
func LoadDir(path string) (*Catalog, error) {
	info, err := os.Stat(path) // #nosec G304 -- caller-supplied via --rules-dir
	if err != nil {
		return nil, fmt.Errorf("rules-dir %q: %w", path, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("rules-dir %q: not a directory", path)
	}
	return LoadFS(os.DirFS(path), ".")
}

// Append concatenates other's rules onto c. Used to layer --rules-dir
// content over the embedded catalog before validation. ID-collision
// handling is the validator's job, not Append's, so duplicates surface
// with line references rather than being silently overwritten here.
func (c *Catalog) Append(other *Catalog) {
	if other == nil {
		return
	}
	c.Rules = append(c.Rules, other.Rules...)
	sort.Slice(c.Rules, func(i, j int) bool { return c.Rules[i].ID < c.Rules[j].ID })
}
