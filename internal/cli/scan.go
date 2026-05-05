package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/esops-dev/esops-go/pkg/config"

	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/exit"
	"github.com/esops-dev/esops-doctor/internal/findings"
	"github.com/esops-dev/esops-doctor/internal/logging"
	"github.com/esops-dev/esops-doctor/internal/probes"
	"github.com/esops-dev/esops-doctor/internal/report"
	"github.com/esops-dev/esops-doctor/internal/rules"
	"github.com/esops-dev/esops-doctor/internal/version"
)

// connectFn is the seam scan tests use to bypass the real cluster.
// Production code never reassigns it; tests swap in a stub that
// returns a *client.Client built with whatever capability fakes the
// test wants. Typed via probes.Connector so this file stays free of a
// direct pkg/client import (TestPkgClientOnlyInProbes-enforced).
var connectFn probes.Connector = probes.Connect

// scanCommand is the diagnostic entry point: load config, resolve the
// target context (or honour --url), connect via probes.Connect, compile
// the embedded rule catalog, evaluate, and emit a report. Exit codes
// follow CLAUDE.md §10; severity-threshold gating uses --fail-on.
func scanCommand() *cli.Command {
	return &cli.Command{
		Name:  "scan",
		Usage: "Diagnose a cluster against the rule catalog",
		Description: "Connects to the cluster identified by --context (or --url),\n" +
			"runs every applicable rule, and prints a report. Exit code 20\n" +
			"signals findings at or above --fail-on; 3/4/5/10 distinguish\n" +
			"cluster-side failures (unreachable / auth / authz / unknown product).",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:      "fail-on",
				Value:     "error",
				Usage:     "Severity threshold for non-zero exit: info | warn | error | critical",
				Validator: validateFailOn,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runScan(ctx, cmd, cmdWriter(cmd))
		},
	}
}

// cmdWriter returns the writer the cli should send report output to.
// urfave/cli propagates the root command's Writer to subcommands; tests
// override it via root.Writer to capture stdout. Falls back to
// os.Stdout when nothing is set so a hand-built command (no urfave
// scaffolding) still produces output.
func cmdWriter(cmd *cli.Command) io.Writer {
	if w := cmd.Root().Writer; w != nil {
		return w
	}
	return os.Stdout
}

func validateFailOn(s string) error {
	if _, err := findings.ParseSeverity(s); err != nil {
		return exit.Usage("--fail-on %q is not supported (accepted: info, warn, error, critical)", s)
	}
	return nil
}

// runScan is the testable core of the command. The output writer is
// injected so tests can capture stdout; logs and structured progress
// continue to flow through slog (stderr by default).
func runScan(ctx context.Context, cmd *cli.Command, stdout io.Writer) error {
	failOn, err := findings.ParseSeverity(cmd.String("fail-on"))
	if err != nil {
		return exit.Usage("%s", err.Error())
	}

	defaults := defaultsFrom(ctx)
	format, err := resolveOutput(cmd, defaults.Output)
	if err != nil {
		return err
	}

	ctxCfg, err := resolveTargetContext(cmd)
	if err != nil {
		return err
	}

	cat, err := loadCatalog()
	if err != nil {
		return err
	}
	eng, err := engine.Compile(cat)
	if err != nil {
		var ce *engine.CompileError
		if errors.As(err, &ce) {
			return exit.Catalog("%s", err.Error())
		}
		return exit.Catalog("compiling rules: %s", err)
	}

	// scanStart is the operator-facing "when the scan ran" timestamp:
	// the moment we begin reaching out to the cluster. duration below
	// measures only the engine phase (prefetch + evaluate) because
	// that's the cost-relevant number for catalog-growth triage; CLI
	// startup and connect are bounded by other timeouts.
	scanStart := time.Now()

	logging.Logger().Info("doctor.scan.connect", "addresses", ctxCfg.Addresses())
	cl, err := connectFn(ctx, ctxCfg)
	if err != nil {
		return err
	}
	dialect := string(cl.Info.Dialect)

	registry := probes.New(cl)

	// Fetch cluster posture (status, node counts) for the report
	// Header before the engine runs. Best-effort: an error here does
	// not fail the scan — the report just renders without the cluster
	// posture fields. Until parallel probe fetching lands this
	// duplicates the call any rule using cluster_health makes.
	healthSummary, healthErr := probes.FetchHealthSummary(ctx, cl)
	if healthErr != nil {
		logging.Logger().Debug("doctor.scan.health_summary.failed", "err", healthErr)
	}

	evalStart := time.Now()
	// Pre-fetch every applicable probe in parallel so the engine can
	// evaluate from cache rather than serialise round trips. Bounded
	// concurrency (DefaultPrefetchConcurrency, currently 4) keeps the
	// cluster from being hit too hard on slow links.
	cache := eng.Prefetch(ctx, registry, dialect, 0)
	results := eng.EvaluateWithCache(ctx, registry, dialect, cache)
	duration := time.Since(evalStart)

	logRuleTimings(results)

	header := report.Header{
		ClusterName:     cl.Info.ClusterName,
		Dialect:         dialect,
		Version:         cl.Info.Version,
		Health:          healthSummary.Status,
		NodeCount:       healthSummary.NumberOfNodes,
		DataNodeCount:   healthSummary.NumberOfDataNodes,
		StartedAt:       scanStart,
		Duration:        duration,
		ToolName:        "esops-doctor",
		ToolVersion:     version.Version,
		ToolCommit:      version.Commit,
		ToolEsopsModule: version.EsopsModule,
	}
	if err := report.Render(format, stdout, header, results, report.Options{
		SummaryOnly: cmd.Bool("summary-only"),
		Quiet:       cmd.Bool("quiet"),
	}); err != nil {
		return fmt.Errorf("rendering report: %w", err)
	}

	if max := report.MaxFailingSeverity(results); max >= failOn {
		// Silent so main does not double-print: the report has already
		// said what failed; the exit-code wrapper carries the marker.
		return exit.Silent(fmt.Errorf("%w: max severity=%s, threshold=%s",
			exit.ErrFindings, max, failOn))
	}
	return nil
}

// logRuleTimings emits one debug-level log line per rule with status,
// duration, and the probe it ran against. Lets a triage flow figure
// out "why is the scan slow" without re-running with extra
// instrumentation — RuleResult.Duration is already populated by the
// engine; this just surfaces it. info-level would be too chatty for
// a 25-rule scan in normal operation, so it sits behind --log-level
// debug.
func logRuleTimings(results []engine.RuleResult) {
	log := logging.Logger()
	for _, r := range results {
		log.Debug("doctor.scan.rule",
			"rule", r.RuleID,
			"status", r.Status.String(),
			"duration_ms", r.Duration.Milliseconds(),
		)
	}
}

// resolveTargetContext picks the cluster to scan against. Priority
// follows the documented precedence: --url overrides everything;
// otherwise the named --context (or current-context) is loaded from the
// esops config file. --cacert / --insecure layer onto either path.
func resolveTargetContext(cmd *cli.Command) (config.Context, error) {
	if u := cmd.String("url"); u != "" {
		ctx := config.Context{
			URL: u,
			TLS: config.TLS{
				CACert:   cmd.String("cacert"),
				Insecure: cmd.Bool("insecure"),
			},
		}
		return ctx, nil
	}

	cfg, _, err := config.LoadDefault(cmd.String("config"))
	if err != nil {
		return config.Context{}, exit.Usage("%s", err.Error())
	}
	_, ctx, err := cfg.ResolveContext(cmd.String("context"))
	if err != nil {
		return config.Context{}, exit.Usage("%s", err.Error())
	}

	// CLI overrides for TLS layer onto whatever the context specified.
	if v := cmd.String("cacert"); v != "" {
		ctx.TLS.CACert = v
	}
	if cmd.IsSet("insecure") {
		ctx.TLS.Insecure = cmd.Bool("insecure")
	}
	return ctx, nil
}

// loadCatalog loads the embedded rule catalog and runs schema +
// probe-name validation. Run before connect so a broken catalog fails
// fast with exit 21 rather than after the operator's auth round-trip.
func loadCatalog() (*rules.Catalog, error) {
	cat, err := rules.LoadEmbedded()
	if err != nil {
		return nil, exit.Catalog("loading embedded rules: %s", err)
	}
	issues := cat.Validate()
	issues = append(issues, cat.ValidateProbes(probes.IsKnown)...)
	if len(issues) > 0 {
		var msgs []string
		for _, e := range issues {
			msgs = append(msgs, e.Error())
		}
		return nil, exit.Catalog("rule catalog invalid:\n  %s", strings.Join(msgs, "\n  "))
	}
	return cat, nil
}
