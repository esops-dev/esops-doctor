package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/urfave/cli/v3"
	yaml "go.yaml.in/yaml/v3"

	"github.com/esops-dev/esops-doctor/internal/exit"
	"github.com/esops-dev/esops-doctor/internal/rules"
)

// explainCommand prints the full description, condition, remediation,
// and doc URL for a single rule. Operators reach for explain when a
// scan flagged something — this is the "what does this finding actually
// mean?" surface that keeps the workflow inside the terminal.
//
// Lookup honours deprecated_aliases so a waiver-rotation period
// continues to map old IDs to current rules without operators hunting
// for the new name.
func explainCommand() *cli.Command {
	return &cli.Command{
		Name:      "explain",
		Usage:     "Print full description, condition, remediation, and doc URL for one rule",
		ArgsUsage: "RULE_ID",
		Description: "Looks up RULE_ID in the catalog (embedded + --rules-dir + user rules.d)\n" +
			"and prints its full metadata. Deprecated aliases resolve to the canonical\n" +
			"rule. --output text (default) is the human-readable form; json and yaml\n" +
			"are scriptable.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "rules-dir",
				Usage: "Additional directory of rule YAML files to layer over the embedded catalog",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runExplain(ctx, cmd, cmdWriter(cmd))
		},
	}
}

// runExplain is the testable core of the command.
func runExplain(ctx context.Context, cmd *cli.Command, stdout io.Writer) error {
	if cmd.NArg() == 0 {
		return exit.Usage("explain requires exactly one RULE_ID argument")
	}
	if cmd.NArg() > 1 {
		return exit.Usage("explain accepts exactly one RULE_ID argument; got %d", cmd.NArg())
	}
	id := strings.TrimSpace(cmd.Args().First())
	if id == "" {
		return exit.Usage("explain requires a non-empty RULE_ID argument")
	}

	format, err := resolveExplainFormat(ctx, cmd)
	if err != nil {
		return err
	}

	cat, err := loadLayeredCatalog(cmd.String("rules-dir"))
	if err != nil {
		return err
	}

	r, ok := lookupRule(cat, id)
	if !ok {
		return exit.Usage("unknown rule %q (run `esops-doctor list-rules` to see available rules)", id)
	}

	switch format {
	case "text":
		return renderExplainText(stdout, r, id)
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(toEntryFull(r))
	case "yaml":
		enc := yaml.NewEncoder(stdout)
		enc.SetIndent(2)
		defer func() { _ = enc.Close() }()
		return enc.Encode(toEntryFull(r))
	default:
		return exit.Usage("--output %q is not supported for explain (accepted: text, json, yaml)", format)
	}
}

// resolveExplainFormat constrains the global --output value to formats
// that make sense for a single-rule dump. "text" is the default — it
// reads as a man-page-shaped block; SARIF/JUnit/HTML are rejected loudly.
//
// "table" is silently mapped to "text": global --output table is the
// default, and treating one rule as a table-of-one would be noise.
func resolveExplainFormat(ctx context.Context, cmd *cli.Command) (string, error) {
	defaults := defaultsFrom(ctx)
	picked := resolveSetting(cmd, "output", defaults.Output, "text")
	switch strings.ToLower(picked) {
	case "", "text", "table":
		return "text", nil
	case "json":
		return "json", nil
	case "yaml":
		return "yaml", nil
	}
	return "", exit.Usage("--output %q is not supported for explain (accepted: text, json, yaml)", picked)
}

// lookupRule finds r in cat by canonical ID first, then by
// deprecated_alias. Returns (rule, true) on the first match. The double
// lookup is what lets `esops-doctor explain old_name` resolve to the
// renamed rule for the duration of the alias's deprecation window.
func lookupRule(cat *rules.Catalog, id string) (rules.Rule, bool) {
	for _, r := range cat.Rules {
		if r.ID == id {
			return r, true
		}
	}
	for _, r := range cat.Rules {
		for _, alias := range r.DeprecatedAliases {
			if alias == id {
				return r, true
			}
		}
	}
	return rules.Rule{}, false
}

// renderExplainText prints a man-page-shaped block: header, then named
// sections. requested is the ID the operator typed; when it differs
// from r.ID the renderer notes the alias resolution so they can update
// their waiver before the alias is removed.
func renderExplainText(w io.Writer, r rules.Rule, requested string) error {
	var b strings.Builder

	fmt.Fprintf(&b, "%s — %s\n", r.ID, r.Name)
	if requested != "" && requested != r.ID {
		fmt.Fprintf(&b, "  (resolved from deprecated alias %q)\n", requested)
	}
	fmt.Fprintf(&b, "  severity: %s\n", r.Severity)
	fmt.Fprintf(&b, "  category: %s\n", r.Category)
	if len(r.Dialects) > 0 {
		fmt.Fprintf(&b, "  dialects: %s\n", strings.Join(r.Dialects, ", "))
	}
	if len(r.Tags) > 0 {
		fmt.Fprintf(&b, "  tags:     %s\n", strings.Join(r.Tags, ", "))
	}
	if r.Effort != "" {
		fmt.Fprintf(&b, "  effort:   %s\n", r.Effort)
	}
	if len(r.AffectedVersions) > 0 {
		fmt.Fprintf(&b, "  versions: %s\n", strings.Join(r.AffectedVersions, ", "))
	}
	if r.Probe != "" {
		fmt.Fprintf(&b, "  probe:    %s\n", r.Probe)
	}
	if r.Source != "" {
		fmt.Fprintf(&b, "  source:   %s\n", r.Source)
	}
	if len(r.DeprecatedAliases) > 0 {
		fmt.Fprintf(&b, "  aliases:  %s\n", strings.Join(r.DeprecatedAliases, ", "))
	}

	if d := strings.TrimSpace(r.Description); d != "" {
		b.WriteString("\nDescription:\n")
		b.WriteString(indent(d, "  "))
		b.WriteString("\n")
	}

	if c := strings.TrimSpace(r.Condition); c != "" {
		b.WriteString("\nCondition (CEL):\n")
		b.WriteString(indent(c, "  "))
		b.WriteString("\n")
	}

	if m := strings.TrimSpace(r.Message); m != "" {
		b.WriteString("\nMessage template:\n")
		b.WriteString(indent(m, "  "))
		b.WriteString("\n")
	}

	if r.Remediation.Command != "" || r.Remediation.DocURL != "" || len(r.Remediation.EsopsCommands) > 0 {
		b.WriteString("\nRemediation:\n")
		if r.Remediation.Command != "" {
			fmt.Fprintf(&b, "  command: %s\n", r.Remediation.Command)
		}
		if r.Remediation.DocURL != "" {
			fmt.Fprintf(&b, "  doc_url: %s\n", r.Remediation.DocURL)
		}
		if len(r.Remediation.EsopsCommands) > 0 {
			b.WriteString("  esops_commands:\n")
			for _, cmd := range r.Remediation.EsopsCommands {
				fmt.Fprintf(&b, "    - %s\n", cmd)
			}
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// indent prefixes every line of s with prefix. Used by renderExplainText
// so multi-line description / condition / message blocks read as
// indented sections instead of running together with the labels.
func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

// explainEntry is the wire shape of explain --output json/yaml.
// Includes everything ruleListEntry has plus the richer fields a
// scriptable consumer cares about (condition, message,
// affected_versions, count_expression, remediation, deprecated_aliases).
type explainEntry struct {
	ID                string             `json:"id" yaml:"id"`
	Name              string             `json:"name" yaml:"name"`
	Category          string             `json:"category" yaml:"category"`
	Severity          string             `json:"severity" yaml:"severity"`
	Description       string             `json:"description,omitempty" yaml:"description,omitempty"`
	Probe             string             `json:"probe" yaml:"probe"`
	Condition         string             `json:"condition,omitempty" yaml:"condition,omitempty"`
	CountExpression   string             `json:"count_expression,omitempty" yaml:"count_expression,omitempty"`
	Message           string             `json:"message,omitempty" yaml:"message,omitempty"`
	Remediation       explainRemediation `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	Tags              []string           `json:"tags,omitempty" yaml:"tags,omitempty"`
	Dialects          []string           `json:"dialects,omitempty" yaml:"dialects,omitempty"`
	AffectedVersions  []string           `json:"affected_versions,omitempty" yaml:"affected_versions,omitempty"`
	Effort            string             `json:"effort,omitempty" yaml:"effort,omitempty"`
	DeprecatedAliases []string           `json:"deprecated_aliases,omitempty" yaml:"deprecated_aliases,omitempty"`
	Source            string             `json:"source,omitempty" yaml:"source,omitempty"`
}

type explainRemediation struct {
	Command       string   `json:"command,omitempty" yaml:"command,omitempty"`
	DocURL        string   `json:"doc_url,omitempty" yaml:"doc_url,omitempty"`
	EsopsCommands []string `json:"esops_commands,omitempty" yaml:"esops_commands,omitempty"`
}

func toEntryFull(r rules.Rule) explainEntry {
	return explainEntry{
		ID:                r.ID,
		Name:              r.Name,
		Category:          r.Category,
		Severity:          r.Severity.String(),
		Description:       strings.TrimSpace(r.Description),
		Probe:             r.Probe,
		Condition:         strings.TrimSpace(r.Condition),
		CountExpression:   strings.TrimSpace(r.CountExpression),
		Message:           r.Message,
		Remediation: explainRemediation{
			Command:       r.Remediation.Command,
			DocURL:        r.Remediation.DocURL,
			EsopsCommands: append([]string(nil), r.Remediation.EsopsCommands...),
		},
		Tags:              append([]string(nil), r.Tags...),
		Dialects:          append([]string(nil), r.Dialects...),
		AffectedVersions:  append([]string(nil), r.AffectedVersions...),
		Effort:            r.Effort,
		DeprecatedAliases: append([]string(nil), r.DeprecatedAliases...),
		Source:            r.Source,
	}
}
