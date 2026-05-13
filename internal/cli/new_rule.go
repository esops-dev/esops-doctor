package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/esops-dev/esops-doctor/internal/exit"
	"github.com/esops-dev/esops-doctor/internal/findings"
	"github.com/esops-dev/esops-doctor/internal/probes"
)

// newRuleCommand scaffolds a YAML rule plus its passing/failing
// fixture file. The on-ramp for a non-Go contributor is one command:
// `esops-doctor new-rule CATEGORY/ID` writes a rule stub and a fixture
// stub, leaving the contributor to fill in the CEL condition and the
// fixture data.
//
// The scaffold is deliberately commented up so a first-time contributor
// reads context as they edit, rather than having to flip back to docs.
// Every field carries a one-line comment naming what fills it.
func newRuleCommand() *cli.Command {
	return &cli.Command{
		Name:      "new-rule",
		Usage:     "Scaffold a YAML rule stub plus passing/failing fixture files",
		ArgsUsage: "CATEGORY/ID",
		Description: "Writes rules/CATEGORY/ID.yaml and testdata/rule_fixtures/ID.yaml\n" +
			"with field-by-field comments. Fill in the CEL condition and fixture\n" +
			"data, then run `make test` to confirm the rule fires as expected.\n\n" +
			"CATEGORY must match one of the existing rule directories\n" +
			"(see rules/) — bootstrap, cluster-settings, destructive-ops,\n" +
			"hygiene, lifecycle, mappings, resource-sanity, security. ID must\n" +
			"be a lowercase snake_case identifier.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "rules-root",
				Value: "rules",
				Usage: "Repo-relative directory holding rule subdirectories (default: rules/)",
			},
			&cli.StringFlag{
				Name:  "fixtures-root",
				Value: filepath.Join("testdata", "rule_fixtures"),
				Usage: "Repo-relative directory holding fixture files (default: testdata/rule_fixtures/)",
			},
			&cli.StringFlag{
				Name:  "probe",
				Value: probes.ClusterHealth,
				Usage: "Probe name the new rule reads against (must be a registered probe; see `esops-doctor probe`)",
			},
			&cli.StringFlag{
				Name:  "severity",
				Value: "warn",
				Usage: "Default severity for the new rule (info | warn | error | critical)",
			},
			&cli.BoolFlag{
				Name:  "force",
				Usage: "Overwrite existing rule / fixture files (default: refuse if either file exists)",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runNewRule(ctx, cmd, cmdWriter(cmd))
		},
	}
}

// ruleIDPattern enforces the lowercase snake_case identifier shape
// every existing rule uses. Kept tight so a misspelled `Heap-Size`
// fails fast — the catalog loader is case-sensitive and a typo'd
// rule_id surfaces only at validate-rules time otherwise.
var ruleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// categoryPattern accepts kebab-case directory names (matching the
// existing rules/ layout) plus snake_case for consistency with rule
// IDs. New rules pick a directory; existence is enforced separately.
var categoryPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

func runNewRule(_ context.Context, cmd *cli.Command, stdout io.Writer) error {
	if cmd.NArg() != 1 {
		return exit.Usage("new-rule requires exactly one CATEGORY/ID argument; got %d", cmd.NArg())
	}
	arg := strings.TrimSpace(cmd.Args().First())
	category, id, ok := strings.Cut(arg, "/")
	if !ok || category == "" || id == "" {
		return exit.Usage("new-rule expects CATEGORY/ID (e.g. resource-sanity/heap_size); got %q", arg)
	}
	if !categoryPattern.MatchString(category) {
		return exit.Usage("category %q is not a valid identifier (lowercase, digits, hyphen/underscore)", category)
	}
	if !ruleIDPattern.MatchString(id) {
		return exit.Usage("rule id %q is not a valid identifier (lowercase, digits, underscore; must start with a letter)", id)
	}

	probe := strings.TrimSpace(cmd.String("probe"))
	if !probes.IsKnown(probe) {
		return exit.Usage("--probe %q is not a registered probe (run `esops-doctor probe` to see the names)", probe)
	}

	// findings.ParseSeverity is the canonical validator the rest of the
	// codebase uses (scan --fail-on, profile loader, waivers loader).
	// Routing through it here keeps "what counts as a severity" in one
	// place rather than drifting between the new-rule scaffold and the
	// loader that will eventually parse the generated YAML.
	severityRaw := strings.TrimSpace(strings.ToLower(cmd.String("severity")))
	sev, err := findings.ParseSeverity(severityRaw)
	if err != nil || sev == findings.SeverityUnknown {
		return exit.Usage("--severity %q is not supported (accepted: info, warn, error, critical)", cmd.String("severity"))
	}
	severity := sev.String()

	rulesRoot := strings.TrimSpace(cmd.String("rules-root"))
	fixturesRoot := strings.TrimSpace(cmd.String("fixtures-root"))
	if rulesRoot == "" || fixturesRoot == "" {
		return exit.Usage("--rules-root and --fixtures-root must not be empty")
	}

	categoryDir := filepath.Join(rulesRoot, category)
	rulePath := filepath.Join(categoryDir, id+".yaml")
	fixturePath := filepath.Join(fixturesRoot, id+".yaml")

	if info, err := os.Stat(categoryDir); err != nil || !info.IsDir() {
		return exit.Usage("category directory %q does not exist (create it first, or pass a valid category)", categoryDir)
	}

	force := cmd.Bool("force")
	if err := assertWritable(rulePath, force); err != nil {
		return err
	}
	if err := assertWritable(fixturePath, force); err != nil {
		return err
	}

	if err := os.WriteFile(rulePath, []byte(renderRuleScaffold(id, category, probe, severity)), 0o600); err != nil {
		return fmt.Errorf("writing rule scaffold %q: %w", rulePath, err)
	}
	if err := os.WriteFile(fixturePath, []byte(renderFixtureScaffold(id)), 0o600); err != nil {
		return fmt.Errorf("writing fixture scaffold %q: %w", fixturePath, err)
	}

	// One Fprintf for the whole next-steps block so the error is
	// checked once rather than six times. Stdout writes generally
	// don't fail, but errcheck won't accept "generally"; one
	// shared check keeps the call site readable.
	if _, err := fmt.Fprintf(stdout, "wrote rule:    %s\nwrote fixture: %s\n\nNext steps:\n"+
		"  1. Edit %s and replace the TODO blocks (condition, message, remediation).\n"+
		"  2. Edit %s and fill in passing/failing fixture data.\n"+
		"  3. Run `make test` to validate the new rule.\n",
		rulePath, fixturePath, rulePath, fixturePath); err != nil {
		return fmt.Errorf("writing scaffold summary: %w", err)
	}
	return nil
}

// assertWritable refuses to clobber a pre-existing rule or fixture
// unless --force is set. New-rule is a contributor on-ramp; silently
// overwriting an existing rule would be a footgun the first time a
// contributor scaffolds against a typo'd ID matching a real file.
func assertWritable(path string, force bool) error {
	_, err := os.Stat(path)
	if err == nil {
		if force {
			return nil
		}
		return exit.Usage("%s already exists (pass --force to overwrite)", path)
	}
	if os.IsNotExist(err) {
		return nil
	}
	return fmt.Errorf("inspecting %q: %w", path, err)
}

// renderRuleScaffold emits the rule YAML stub. Every field carries a
// short comment so an editor can see what fills it without flipping
// to docs. The condition is intentionally `false` so the rule fires
// against the failing fixture out of the box — a no-op condition
// (`true`) would make `make test` pass without any work, hiding the
// fact that the contributor still needs to write the rule.
func renderRuleScaffold(id, category, probe, severity string) string {
	categoryField := strings.ReplaceAll(category, "-", "_")
	return fmt.Sprintf(`checks:
  - id: %s
    # Human-readable rule title (one line).
    name: TODO summary of what this rule checks
    category: %s
    severity: %s
    # Multi-line: explain *why* this matters and what the operator
    # should do about it. Wrapped at ~72 columns for terminal display.
    description: >
      TODO describe the anti-pattern this rule catches, the impact on
      the cluster, and the corrective action.
    probe: %s
    # CEL expression over self. self is the raw probe shape — run
    # `+"`esops-doctor probe %s`"+` against a live cluster to see it.
    # Return true when the cluster is *healthy* (rule passes); false
    # when the anti-pattern is present (rule fails).
    condition: |
      false
    # Optional: int-typed CEL expression for the {{count}} placeholder
    # in the message. Drop this block if the rule does not use a count.
    count_expression: |
      1
    # Surfaced verbatim in the report. {{count}} is substituted when
    # count_expression is set.
    message: TODO one-line operator-facing failure message.
    remediation:
      command: TODO one-line "how to fix" instruction
      doc_url: https://www.elastic.co/guide/en/elasticsearch/reference/current/
      esops_commands: []
    tags: [%s]
    dialects: [elasticsearch, opensearch]
    affected_versions: ["7.x", "8.x", "9.x", "1.x", "2.x", "3.x"]
    effort: medium
`, id, categoryField, severity, probe, probe, category)
}

// renderFixtureScaffold emits the fixture YAML with one pass and one
// fail case. Pre-stubbed so the contributor only needs to fill in the
// `data:` payload — the structure is in place.
func renderFixtureScaffold(id string) string {
	return fmt.Sprintf(`rule: %s
cases:
  - name: TODO describe the passing case
    expect: pass
    data:
      # TODO probe-shaped data that should NOT trip the condition

  - name: TODO describe the failing case
    expect: fail
    data:
      # TODO probe-shaped data that SHOULD trip the condition
`, id)
}
