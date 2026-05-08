package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/urfave/cli/v3"
	yaml "go.yaml.in/yaml/v3"

	"github.com/esops-dev/esops-doctor/internal/exit"
	"github.com/esops-dev/esops-doctor/internal/logging"
	"github.com/esops-dev/esops-doctor/internal/rules"
)

// listRulesCommand prints the catalog the next scan would evaluate.
// Honors the same `--rules-dir` and selector flags as scan so an
// operator can preview "what will run" before committing to a real
// connect. Output respects the global --output flag for table | json |
// yaml; the SARIF / JUnit / HTML formats are scan-specific and rejected
// here loudly rather than emitting nonsense.
func listRulesCommand() *cli.Command {
	return &cli.Command{
		Name:  "list-rules",
		Usage: "Print the rule catalog with metadata",
		Description: "Lists every rule in the catalog (embedded + --rules-dir + user rules.d),\n" +
			"optionally narrowed by --tags / --skip-tags / --rule-id. The default table\n" +
			"format shows id, severity, category, dialects, and tags; --output json or\n" +
			"yaml emits a structured form for scripting.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "rules-dir",
				Usage: "Additional directory of rule YAML files to layer over the embedded catalog",
			},
			&cli.StringSliceFlag{
				Name:  "tags",
				Usage: "Show only rules carrying at least one of these tags (repeatable or comma-separated)",
			},
			&cli.StringSliceFlag{
				Name:  "skip-tags",
				Usage: "Hide rules carrying any of these tags (repeatable or comma-separated)",
			},
			&cli.StringSliceFlag{
				Name:  "rule-id",
				Usage: "Show only the named rules (repeatable or comma-separated)",
			},
			&cli.BoolFlag{
				Name: "coverage",
				Usage: "Print which in-scope buckets from the design scope are covered by the catalog and which are not " +
					"(operates on the unfiltered catalog; --tags / --skip-tags / --rule-id are ignored, " +
					"because the question the flag answers is about catalog completeness, not run scope)",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runListRules(ctx, cmd, cmdWriter(cmd))
		},
	}
}

// runListRules is the testable core: parameters resolved, output writer
// injected. Tests invoke this directly with a buffer to avoid wiring the
// whole urfave entry point.
func runListRules(ctx context.Context, cmd *cli.Command, stdout io.Writer) error {
	format, err := resolveListFormat(ctx, cmd)
	if err != nil {
		return err
	}

	cat, err := loadLayeredCatalog(cmd.String("rules-dir"))
	if err != nil {
		return err
	}

	// --coverage operates on the unfiltered catalog: the question the
	// flag answers is "is the catalog covering the design scope?", and
	// honouring --tags / --rule-id here would conflate "what's in the
	// catalog" with "what's in this run". Filtering still happens for
	// the regular --output paths below.
	if cmd.Bool("coverage") {
		// Warn loudly when an operator pairs --coverage with a filter
		// flag — the flag is silently ignored by design, but a
		// stderr-side notice keeps the behaviour from surprising
		// anyone who expected the filter to narrow the buckets.
		if len(cmd.StringSlice("rule-id")) > 0 ||
			len(cmd.StringSlice("tags")) > 0 ||
			len(cmd.StringSlice("skip-tags")) > 0 {
			logging.Logger().Warn(
				"doctor.list_rules.coverage.filters_ignored",
				"reason", "--coverage operates on the full catalog; --rule-id / --tags / --skip-tags ignored")
		}
		doc := computeCoverage(cat.Rules)
		switch format {
		case "table":
			return renderCoverageTable(stdout, doc)
		case "json":
			return renderCoverageJSON(stdout, doc)
		case "yaml":
			return renderCoverageYAML(stdout, doc)
		}
	}

	filtered, _ := applyCatalogFilter(cat, catalogFilter{
		RuleIDs:     cmd.StringSlice("rule-id"),
		IncludeTags: cmd.StringSlice("tags"),
		SkipTags:    cmd.StringSlice("skip-tags"),
	})
	if filtered == nil {
		filtered = cat
	}

	switch format {
	case "table":
		return renderRulesTable(stdout, filtered.Rules)
	case "json":
		return renderRulesJSON(stdout, filtered.Rules)
	case "yaml":
		return renderRulesYAML(stdout, filtered.Rules)
	default:
		// resolveListFormat already enforces the supported set; this
		// branch is the type-safety belt.
		return exit.Usage("--output %q is not supported for list-rules (accepted: table, json, yaml)", format)
	}
}

// resolveListFormat reads the global --output flag and constrains it to
// the formats list-rules can render. SARIF, JUnit, and HTML are
// scan-specific report shapes; emitting them for a static rule listing
// would produce nonsense, so the command rejects them with exit 2.
func resolveListFormat(ctx context.Context, cmd *cli.Command) (string, error) {
	defaults := defaultsFrom(ctx)
	picked := resolveSetting(cmd, "output", defaults.Output, "table")
	switch strings.ToLower(picked) {
	case "table", "json", "yaml":
		return strings.ToLower(picked), nil
	}
	return "", exit.Usage("--output %q is not supported for list-rules (accepted: table, json, yaml)", picked)
}

// ruleListEntry is the wire shape of one rule in --output json / yaml.
// Mirrors the fields the table prints plus a few extras (effort,
// description) that scripts often want without re-running explain. The
// schema version is exported alongside the rules slice via
// ruleListDoc; bumping it would be a deliberate, breaking change.
type ruleListEntry struct {
	ID          string   `json:"id" yaml:"id"`
	Name        string   `json:"name" yaml:"name"`
	Category    string   `json:"category" yaml:"category"`
	Severity    string   `json:"severity" yaml:"severity"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Probe       string   `json:"probe" yaml:"probe"`
	Tags        []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	Dialects    []string `json:"dialects,omitempty" yaml:"dialects,omitempty"`
	Effort      string   `json:"effort,omitempty" yaml:"effort,omitempty"`
	Source      string   `json:"source,omitempty" yaml:"source,omitempty"`
}

type ruleListDoc struct {
	SchemaVersion int             `json:"schema_version" yaml:"schema_version"`
	Rules         []ruleListEntry `json:"rules" yaml:"rules"`
}

func toEntry(r rules.Rule) ruleListEntry {
	return ruleListEntry{
		ID:          r.ID,
		Name:        r.Name,
		Category:    r.Category,
		Severity:    r.Severity.String(),
		Description: strings.TrimSpace(r.Description),
		Probe:       r.Probe,
		Tags:        append([]string(nil), r.Tags...),
		Dialects:    append([]string(nil), r.Dialects...),
		Effort:      r.Effort,
		Source:      r.Source,
	}
}

// renderRulesTable emits a tab-aligned listing with id, severity,
// category, dialects, and tags. The columns match the user story in
// ROADMAP.md (Milestone 5) so an operator scanning the output can plan
// which rules apply at a glance.
func renderRulesTable(w io.Writer, rs []rules.Rule) error {
	if len(rs) == 0 {
		_, err := fmt.Fprintln(w, "No rules match the current selection.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "ID\tSEVERITY\tCATEGORY\tDIALECTS\tTAGS"); err != nil {
		return err
	}
	for _, r := range rs {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			r.ID,
			r.Severity.String(),
			r.Category,
			strings.Join(r.Dialects, ","),
			strings.Join(r.Tags, ","),
		); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "\n%d rule(s)\n", len(rs))
	return err
}

func renderRulesJSON(w io.Writer, rs []rules.Rule) error {
	doc := ruleListDoc{SchemaVersion: 1, Rules: make([]ruleListEntry, 0, len(rs))}
	for _, r := range rs {
		doc.Rules = append(doc.Rules, toEntry(r))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func renderRulesYAML(w io.Writer, rs []rules.Rule) error {
	doc := ruleListDoc{SchemaVersion: 1, Rules: make([]ruleListEntry, 0, len(rs))}
	for _, r := range rs {
		doc.Rules = append(doc.Rules, toEntry(r))
	}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	defer func() { _ = enc.Close() }()
	return enc.Encode(doc)
}
