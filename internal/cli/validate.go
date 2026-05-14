package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/urfave/cli/v3"

	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/exit"
	"github.com/esops-dev/esops-doctor/internal/probes"
	"github.com/esops-dev/esops-doctor/internal/rules"
)

func validateRulesCommand() *cli.Command {
	return &cli.Command{
		Name:  "validate-rules",
		Usage: "Lint the rule catalog (schema check)",
		Description: "Validates the layered rule catalog: embedded core, --rules-dir, and\n" +
			"the user rules.d directory ($XDG_CONFIG_HOME/esops-doctor/rules.d/, or\n" +
			"$HOME/.config/esops-doctor/rules.d/). Schema fields are checked, IDs\n" +
			"verified unique, severities and dialects constrained, probe names resolved\n" +
			"against the registered adapter set, and each rule's CEL condition is\n" +
			"compiled to catch syntax and type errors.\n\n" +
			"With --strict, also asserts every rule has a fixture file alongside\n" +
			"testdata/rule_fixtures/<id>.yaml carrying at least one pass and one\n" +
			"fail case — the same gate CI's TestEveryRuleHasFixtures enforces.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "rules-dir",
				Usage: "Additional directory of rule YAML files to validate alongside the embedded catalog",
			},
			&cli.StringFlag{
				Name:  "rules-pack",
				Usage: "Validate a signed rule pack alongside the embedded catalog (MANIFEST.yaml integrity-checked before any rule YAML is parsed)",
			},
			&cli.BoolFlag{
				Name:  "strict",
				Usage: "Also require each rule to have a fixture file with at least one pass case and one fail case",
			},
			&cli.StringFlag{
				Name:  "fixtures-dir",
				Usage: "Directory holding rule fixture YAML files (default: testdata/rule_fixtures); ignored unless --strict is set",
				Value: filepath.Join("testdata", "rule_fixtures"),
			},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			return runValidateRules(os.Stdout, os.Stderr,
				cmd.String("rules-dir"),
				cmd.String("rules-pack"),
				cmd.Bool("strict"),
				cmd.String("fixtures-dir"))
		},
	}
}

// runValidateRules is split out for testability: tests can hand it
// their own writers and inspect the resulting strings.
//
// Catalog assembly mirrors scan / list-rules / explain so an operator
// validating a rule sees exactly what the rest of the tool would run
// against. The per-issue stderr printing (one violation per line) is
// unique to this command — operators iterating on a rule want each
// problem addressable in isolation, not a single bundled error blob.
//
// With strict=true, every rule must have a fixture file at
// fixturesDir/<id>.yaml containing at least one pass and one fail
// case — the same contract TestEveryRuleHasFixtures enforces in CI,
// callable locally as one command.
func runValidateRules(stdout, stderr io.Writer, rulesDir, rulesPack string, strict bool, fixturesDir string) error {
	cat, err := assembleLayeredCatalogWithPack(rulesDir, rulesPack)
	if err != nil {
		return err
	}

	issues := cat.Validate()
	issues = append(issues, cat.ValidateProbes(probes.IsKnown)...)

	// CEL compile is run only when schema validation passed: a rule
	// missing required fields will already have surfaced as an issue,
	// and feeding it to the CEL compiler produces noise on top of the
	// real problem. Operators see schema errors first, fix those, then
	// re-run to surface CEL errors.
	if len(issues) == 0 {
		if _, err := engine.Compile(cat); err != nil {
			var ce *engine.CompileError
			if errors.As(err, &ce) {
				for _, f := range ce.Failures {
					issues = append(issues, rules.ValidationError{
						Source:  f.Source,
						RuleID:  f.RuleID,
						Message: "CEL: " + f.Message,
					})
				}
			} else {
				return exit.Catalog("compiling rules: %s", err)
			}
		}
	}

	if strict {
		issues = append(issues, validateFixtures(cat, fixturesDir)...)
	}

	if len(issues) == 0 {
		_, _ = fmt.Fprintf(stdout, "OK: %d rule(s) validated\n", len(cat.Rules))
		return nil
	}
	for _, e := range issues {
		_, _ = fmt.Fprintln(stderr, e.Error())
	}
	_, _ = fmt.Fprintf(stderr, "%d issue(s) across %d rule(s)\n", len(issues), len(cat.Rules))
	return exit.Catalog("rule catalog validation failed")
}

// fixtureShape mirrors testdata/rule_fixtures schema enough to count
// pass/fail cases. Kept private here rather than imported from the
// engine tests — engine_test exposes the type from a `_test.go` file,
// and the catalog-hygiene gate needs to run from production code so
// `validate-rules --strict` can fire from a shipped binary.
type fixtureShape struct {
	Rule  string `yaml:"rule"`
	Cases []struct {
		Name   string `yaml:"name"`
		Expect string `yaml:"expect"`
	} `yaml:"cases"`
}

// validateFixtures asserts every rule in cat has a fixture file at
// fixturesDir/<id>.yaml with at least one pass case and one fail
// case. Missing dir / unreadable fixture / malformed YAML surface as
// catalog-validation issues so an operator running locally sees the
// same diagnostics CI would.
//
// Embedded-only rules (Source under embedded fs, no leading path
// separator) are always checked. --rules-dir and user rules.d rules
// are skipped: an operator's downstream pack lives outside the doctor
// repository's testdata tree, so we can't reasonably assert fixture
// presence for them.
func validateFixtures(cat *rules.Catalog, fixturesDir string) []rules.ValidationError {
	var errs []rules.ValidationError
	if fixturesDir == "" {
		fixturesDir = filepath.Join("testdata", "rule_fixtures")
	}
	for _, r := range cat.Rules {
		if !isEmbeddedRule(r) {
			continue
		}
		path := filepath.Join(fixturesDir, r.ID+".yaml")
		data, err := os.ReadFile(path) // #nosec G304 -- fixturesDir is operator-provided
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, rules.ValidationError{
					Source:  r.Source,
					RuleID:  r.ID,
					Message: fmt.Sprintf("missing fixture file %s (run with --fixtures-dir to point at a different location)", path),
				})
				continue
			}
			errs = append(errs, rules.ValidationError{
				Source:  r.Source,
				RuleID:  r.ID,
				Message: fmt.Sprintf("reading fixture %s: %s", path, err),
			})
			continue
		}
		var f fixtureShape
		if uerr := yaml.Unmarshal(data, &f); uerr != nil {
			errs = append(errs, rules.ValidationError{
				Source:  path,
				RuleID:  r.ID,
				Message: fmt.Sprintf("parsing fixture: %s", uerr),
			})
			continue
		}
		if f.Rule != "" && f.Rule != r.ID {
			errs = append(errs, rules.ValidationError{
				Source:  path,
				RuleID:  r.ID,
				Message: fmt.Sprintf("fixture rule %q does not match rule id %q", f.Rule, r.ID),
			})
		}
		var hasPass, hasFail bool
		for _, c := range f.Cases {
			switch strings.ToLower(c.Expect) {
			case "pass":
				hasPass = true
			case "fail":
				hasFail = true
			}
		}
		if !hasPass || !hasFail {
			errs = append(errs, rules.ValidationError{
				Source:  path,
				RuleID:  r.ID,
				Message: fmt.Sprintf("fixture must declare at least one pass case and one fail case (have pass=%v, fail=%v)", hasPass, hasFail),
			})
		}
	}
	return errs
}

// isEmbeddedRule reports whether r came from the binary's embedded
// catalog (vs. --rules-dir or the user rules.d). The embed FS uses
// forward-slash paths anchored at "rules/"; on-disk loaders see an
// absolute or platform-specific path. The split lets --strict gate the
// shipped catalog without blowing up on operator packs that legitimately
// have no fixtures.
func isEmbeddedRule(r rules.Rule) bool {
	if r.Source == "" {
		return false
	}
	// Embedded sources are forward-slash, "rules/<cat>/<id>.yaml" — no
	// volume / drive prefix and no leading separator.
	if filepath.IsAbs(r.Source) {
		return false
	}
	return strings.HasPrefix(r.Source, "rules/")
}
