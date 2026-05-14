package cli

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/urfave/cli/v3"

	esopsdoctor "github.com/esops-dev/esops-doctor"
	"github.com/esops-dev/esops-doctor/internal/exit"
	"github.com/esops-dev/esops-doctor/internal/rules"
)

// docsCommand is the documentation-generation entry point: render the
// rule catalog as Markdown, or write the embedded JSON Schema files to
// disk for an editor / yaml-language-server to consume. Output is the
// same data the binary already ships — the generator's job is to keep
// the docs site and editor configs from drifting.
func docsCommand() *cli.Command {
	return &cli.Command{
		Name:  "docs",
		Usage: "Render the rule catalog as Markdown or write the JSON Schema files",
		Description: "Generates operator-facing documentation from the same YAML that\n" +
			"ships in the binary. `docs rules` writes the rule reference;\n" +
			"`docs schemas` extracts the embedded JSON Schema files so a\n" +
			"YAML editor can validate rule / profile / waiver authoring.",
		Commands: []*cli.Command{
			docsRulesCommand(),
			docsSchemasCommand(),
		},
	}
}

// docsRulesCommand renders the catalog as Markdown. The output is the
// same data `list-rules` and `explain` surface — emitted as a static
// document so the repo's docs site stays in sync with the embedded
// catalog without a separate review step.
//
// `--rules-dir` lets a downstream pack render its own catalog (the
// embedded core is still included; the operator filters with `--tags`
// or post-processes the Markdown). Output goes to stdout by default;
// `--output-file PATH` redirects so `make docs` can pipe the result
// into the repo's docs tree.
func docsRulesCommand() *cli.Command {
	return &cli.Command{
		Name:  "rules",
		Usage: "Render the rule catalog as Markdown (the docs/rules-reference.md source)",
		Description: "Walks the layered catalog and emits a single Markdown document grouping\n" +
			"rules by category. Each entry carries id, severity, dialects, tags, the\n" +
			"prose description, and the CEL condition. Pipe to a file or use\n" +
			"--output-file to write directly.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "rules-dir",
				Usage: "Additional directory of rule YAML files to layer over the embedded catalog",
			},
			&cli.StringFlag{
				Name:  "rules-pack",
				Usage: "Render a signed rule pack alongside the embedded catalog (MANIFEST.yaml integrity-checked before loading)",
			},
			&cli.StringFlag{
				Name:  "output-file",
				Usage: "Write the Markdown to PATH instead of stdout (file written with mode 0644)",
			},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			return runDocsRules(cmd, cmdWriter(cmd))
		},
	}
}

// docsSchemasCommand extracts the embedded JSON Schema files for the
// rule, profile, and waiver YAML shapes. Operators point their YAML
// language server at the result to surface validation errors as they
// type. The schemas live in the binary so an airgapped install does
// not need to fetch them separately.
func docsSchemasCommand() *cli.Command {
	return &cli.Command{
		Name:  "schemas",
		Usage: "Write the embedded JSON Schema files (rule / profile / waiver) to a directory",
		Description: "Writes rule.schema.json, profile.schema.json, and waiver.schema.json\n" +
			"into --output-dir (default: current directory). Configure your YAML\n" +
			"language server to validate rule files against rule.schema.json, profile\n" +
			"files against profile.schema.json, and waiver files against\n" +
			"waiver.schema.json. With no arguments, prints each schema's name and size\n" +
			"to stdout so an operator can confirm what would be written.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "output-dir",
				Usage: "Directory to write the schema files into (default: print the embedded list to stdout)",
			},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			return runDocsSchemas(cmd, cmdWriter(cmd))
		},
	}
}

// runDocsRules assembles the layered catalog (so a downstream pack
// shows up in the rendered Markdown) and prints the rule reference. We
// deliberately do not run engine.Compile — the document is for human
// consumption; an authoring CEL error is caught by validate-rules.
func runDocsRules(cmd *cli.Command, stdout io.Writer) error {
	cat, err := loadLayeredCatalogWithPack(cmd.String("rules-dir"), cmd.String("rules-pack"))
	if err != nil {
		return err
	}

	out := stdout
	if path := strings.TrimSpace(cmd.String("output-file")); path != "" {
		f, ferr := openTruncatedFile(path)
		if ferr != nil {
			return exit.Usage("opening --output-file %q: %s", path, ferr)
		}
		defer func() { _ = f.Close() }()
		out = f
	}

	return renderRulesMarkdown(out, cat.Rules)
}

// renderRulesMarkdown writes a single Markdown document grouping the
// rules by category. The order within a category is the catalog's
// canonical sort-by-id so the diff between runs is stable.
//
// Fields surfaced: severity, dialects, tags, effort, probe, description,
// condition, message, count_expression (when set), remediation. The
// schema_version line at the top lets a future generator change shape
// without breaking existing pipelines.
func renderRulesMarkdown(w io.Writer, rs []rules.Rule) error {
	var b strings.Builder
	b.WriteString("# Rule reference\n\n")
	b.WriteString("Generated from the embedded catalog by `esops-doctor docs rules`. " +
		"Do not edit by hand — change the rule YAML and regenerate.\n\n")
	fmt.Fprintf(&b, "Total rules: **%d**.\n\n", len(rs))

	byCategory := make(map[string][]rules.Rule)
	for _, r := range rs {
		cat := r.Category
		if cat == "" {
			cat = "uncategorised"
		}
		byCategory[cat] = append(byCategory[cat], r)
	}
	categories := make([]string, 0, len(byCategory))
	for c := range byCategory {
		categories = append(categories, c)
	}
	sort.Strings(categories)

	b.WriteString("## Table of contents\n\n")
	for _, c := range categories {
		fmt.Fprintf(&b, "- [%s](#%s) — %d rule(s)\n", c, anchorize(c), len(byCategory[c]))
	}
	b.WriteString("\n")

	for _, c := range categories {
		fmt.Fprintf(&b, "## %s\n\n", c)
		for _, r := range byCategory[c] {
			renderRuleMarkdown(&b, r)
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func renderRuleMarkdown(b *strings.Builder, r rules.Rule) {
	fmt.Fprintf(b, "### `%s`\n\n", r.ID)
	fmt.Fprintf(b, "**%s**\n\n", r.Name)
	fmt.Fprintf(b, "| Severity | Dialects | Effort | Tags |\n")
	fmt.Fprintf(b, "|---|---|---|---|\n")
	tags := strings.Join(r.Tags, ", ")
	if tags == "" {
		tags = "—"
	}
	effort := r.Effort
	if effort == "" {
		effort = "—"
	}
	fmt.Fprintf(b, "| %s | %s | %s | %s |\n\n",
		r.Severity.String(),
		strings.Join(r.Dialects, ", "),
		effort,
		tags)

	if d := strings.TrimSpace(r.Description); d != "" {
		b.WriteString(d)
		b.WriteString("\n\n")
	}

	fmt.Fprintf(b, "- **Probe:** `%s`\n", r.Probe)
	if len(r.AffectedVersions) > 0 {
		fmt.Fprintf(b, "- **Affected versions:** %s\n", strings.Join(r.AffectedVersions, ", "))
	}
	if len(r.DeprecatedAliases) > 0 {
		fmt.Fprintf(b, "- **Deprecated aliases:** %s\n", strings.Join(r.DeprecatedAliases, ", "))
	}
	b.WriteString("\n")

	if cond := strings.TrimSpace(r.Condition); cond != "" {
		b.WriteString("**Condition (CEL):**\n\n")
		b.WriteString("```cel\n")
		b.WriteString(cond)
		if !strings.HasSuffix(cond, "\n") {
			b.WriteString("\n")
		}
		b.WriteString("```\n\n")
	}

	if cnt := strings.TrimSpace(r.CountExpression); cnt != "" {
		b.WriteString("**Count expression (CEL):**\n\n")
		b.WriteString("```cel\n")
		b.WriteString(cnt)
		if !strings.HasSuffix(cnt, "\n") {
			b.WriteString("\n")
		}
		b.WriteString("```\n\n")
	}

	if msg := strings.TrimSpace(r.Message); msg != "" {
		fmt.Fprintf(b, "**Message template:** %s\n\n", msg)
	}

	if r.Remediation.Command != "" || r.Remediation.DocURL != "" || len(r.Remediation.EsopsCommands) > 0 {
		b.WriteString("**Remediation:**\n\n")
		if r.Remediation.Command != "" {
			fmt.Fprintf(b, "- Command: %s\n", r.Remediation.Command)
		}
		if r.Remediation.DocURL != "" {
			fmt.Fprintf(b, "- Doc: <%s>\n", r.Remediation.DocURL)
		}
		for _, c := range r.Remediation.EsopsCommands {
			fmt.Fprintf(b, "- `%s`\n", c)
		}
		b.WriteString("\n")
	}

	b.WriteString("---\n\n")
}

// anchorize converts a category name into a GitHub-flavoured Markdown
// anchor. Lower-cases, replaces underscores with hyphens, strips
// anything not alphanumeric or hyphen. Matches the slug behaviour of
// the GitHub renderer so the Table-of-contents links land on the right
// heading.
func anchorize(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == ' ':
			b.WriteRune('-')
		}
	}
	return b.String()
}

// runDocsSchemas writes the embedded JSON Schema files to --output-dir.
// With no flag, prints the embedded names and sizes — useful for
// confirming the binary ships the expected set without touching disk.
func runDocsSchemas(cmd *cli.Command, stdout io.Writer) error {
	dir := strings.TrimSpace(cmd.String("output-dir"))
	entries, err := listSchemaEntries()
	if err != nil {
		return fmt.Errorf("reading embedded schemas: %w", err)
	}
	if dir == "" {
		for _, e := range entries {
			if _, err := fmt.Fprintf(stdout, "%s\t%d bytes\n", e.name, len(e.data)); err != nil {
				return err
			}
		}
		return nil
	}
	if err := ensureDir(dir); err != nil {
		return exit.Usage("creating --output-dir %q: %s", dir, err)
	}
	for _, e := range entries {
		target := filepath.Join(dir, e.name)
		if err := writeFile(target, e.data); err != nil {
			return fmt.Errorf("writing %s: %w", target, err)
		}
		if _, err := fmt.Fprintf(stdout, "wrote %s\n", target); err != nil {
			return err
		}
	}
	return nil
}

// schemaEntry is one embedded schema document: filename plus the raw
// bytes shipped under schemas/. Surfaced from listSchemaEntries so
// callers (the command, tests) walk the same source of truth.
type schemaEntry struct {
	name string
	data []byte
}

// listSchemaEntries walks the embedded schemas/ tree and returns the
// shipped documents in sort order. The walk treats schemas/ as flat —
// any future subdirectories would need a layout change before they can
// be exposed, so a typo'd nested file fails the test rather than
// silently being included.
func listSchemaEntries() ([]schemaEntry, error) {
	var out []schemaEntry
	err := fs.WalkDir(esopsdoctor.Schemas, "schemas", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".json") {
			return nil
		}
		data, readErr := fs.ReadFile(esopsdoctor.Schemas, path)
		if readErr != nil {
			return readErr
		}
		out = append(out, schemaEntry{name: filepath.Base(path), data: data})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// openTruncatedFile opens path for writing, creating it if missing or
// truncating it if present. Mode 0600 matches the rest of the codebase
// (write-logs, waivers) — the generated Markdown may include
// remediation hints, which we keep operator-readable but not
// world-readable by default.
func openTruncatedFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- caller-supplied via --output-file
}

// ensureDir creates dir (and any missing parents) when it does not yet
// exist. A bare os.MkdirAll on a pre-existing file would also succeed,
// so we sanity-check the existing path is a directory before returning.
func ensureDir(dir string) error {
	if info, err := os.Stat(dir); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%s exists and is not a directory", dir)
		}
		return nil
	}
	return os.MkdirAll(dir, 0o750)
}

// writeFile creates or truncates path with the given bytes. Mode 0644
// because schema files are operator-shared (an editor / language
// server reads them under the operator's account, but other tools
// running as a different user — pre-commit hooks, CI — should still
// see them).
func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644) // #nosec G306 -- editor-shared file
}
