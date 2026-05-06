package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

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
			"compiled to catch syntax and type errors.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "rules-dir",
				Usage: "Additional directory of rule YAML files to validate alongside the embedded catalog",
			},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			return runValidateRules(os.Stdout, os.Stderr, cmd.String("rules-dir"))
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
func runValidateRules(stdout, stderr io.Writer, rulesDir string) error {
	cat, err := assembleLayeredCatalog(rulesDir)
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
