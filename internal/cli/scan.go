package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
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
	"github.com/esops-dev/esops-doctor/internal/profiles"
	"github.com/esops-dev/esops-doctor/internal/report"
	"github.com/esops-dev/esops-doctor/internal/rules"
	"github.com/esops-dev/esops-doctor/internal/version"
	"github.com/esops-dev/esops-doctor/internal/waivers"
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
// follow the documented schedule (3 cluster unreachable, 4 auth, 5 authz,
// 10 unknown product, 20 findings ≥ threshold); severity-threshold
// gating uses --fail-on.
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
			&cli.StringFlag{
				Name:  "profile",
				Usage: "Named profile to apply: prod | staging | dev | ci | cis-bench | <embedded name>",
			},
			&cli.StringFlag{
				Name:  "rules-dir",
				Usage: "Additional directory of rule YAML files layered over the embedded catalog and the user rules.d",
			},
			&cli.StringSliceFlag{
				Name:  "tags",
				Usage: "Run only rules carrying at least one of these tags (repeatable or comma-separated)",
			},
			&cli.StringSliceFlag{
				Name:  "skip-tags",
				Usage: "Skip rules carrying any of these tags (repeatable or comma-separated)",
			},
			&cli.StringSliceFlag{
				Name:  "rule-id",
				Usage: "Run only the named rules (repeatable or comma-separated)",
			},
			&cli.StringFlag{
				Name:  "waivers",
				Usage: "Path to a waivers YAML file (default: .esops-doctor.yaml in cwd or user config)",
			},
			&cli.BoolFlag{
				Name:  "cluster-waivers",
				Usage: "Also read suppressions from the .esops-doctor-waivers index (not yet implementable: pkg/client lacks document-read capability)",
			},
			&cli.StringSliceFlag{
				Name:  "targets",
				Usage: "Multi-cluster fan-out: comma-separated context names from the esops config (repeatable)",
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

	if cmd.Bool("cluster-waivers") {
		// Doctor's read-only-by-construction model forbids reaching
		// around pkg/client to read cluster documents directly. The
		// upstream document-read capability now exists; wiring it
		// through into a cluster-side waiver source is its own
		// milestone. Until then the flag's name stays reserved and
		// discoverable, and operators get a clear "not yet" rather
		// than a silent no-op.
		return exit.Usage("--cluster-waivers is documented but not yet implemented; " +
			"file-based waivers via --waivers are wired and ready")
	}

	defaults := defaultsFrom(ctx)
	format, err := resolveOutput(cmd, defaults.Output)
	if err != nil {
		return err
	}

	multiTargets, isMulti, err := resolveMultiTargets(cmd)
	if err != nil {
		return err
	}

	eng, waiverSet, err := buildEngineAndWaivers(cmd)
	if err != nil {
		return err
	}

	opts := report.Options{
		SummaryOnly: cmd.Bool("summary-only"),
		Quiet:       cmd.Bool("quiet"),
	}

	if isMulti {
		return runMultiClusterScan(ctx, stdout, format, opts, failOn, eng, waiverSet, multiTargets)
	}

	ctxCfg, err := resolveTargetContext(cmd)
	if err != nil {
		return err
	}
	target := targetSpec{Label: ctxCfg.URL, Context: ctxCfg}

	outcome := scanOneCluster(ctx, eng, waiverSet, target)
	if outcome.connectErr != nil {
		return outcome.connectErr
	}

	if err := report.Render(format, stdout, outcome.Header, outcome.Results, opts); err != nil {
		return fmt.Errorf("rendering report: %w", err)
	}

	if max := report.MaxFailingSeverity(outcome.Results); max >= failOn {
		// Silent so main does not double-print: the report has already
		// said what failed; the exit-code wrapper carries the marker.
		return exit.Silent(fmt.Errorf("%w: max severity=%s, threshold=%s",
			exit.ErrFindings, max, failOn))
	}
	return nil
}

// buildEngineAndWaivers loads the embedded + layered rule catalog,
// applies --profile and --tags / --skip-tags / --rule-id filters, loads
// the waivers file and resolves deprecated-alias keys, then compiles
// the engine. The compiled engine is reusable across multiple targets
// — it carries no per-cluster state — so a multi-cluster scan compiles
// once and prefetches/evaluates against each cluster in turn.
func buildEngineAndWaivers(cmd *cli.Command) (*engine.Engine, *waivers.Set, error) {
	fullCat, err := loadLayeredCatalog(cmd.String("rules-dir"))
	if err != nil {
		return nil, nil, err
	}
	cat, err := applyProfile(cmd, fullCat)
	if err != nil {
		return nil, nil, err
	}
	cat = applyScanFilters(cmd, cat)

	waiverSet, err := loadWaivers(cmd)
	if err != nil {
		return nil, nil, err
	}
	// Resolve waivers keyed by deprecated_alias against the unfiltered
	// catalog so an alias used in a waiver still matches when the
	// profile dropped the rule (or didn't). The cli is the join point;
	// the waivers package stays catalog-agnostic.
	if !waiverSet.Empty() {
		aliases := aliasIndex(fullCat)
		waiverSet.ResolveAliases(aliases, func(alias, canonical string) {
			logging.Logger().Debug("doctor.scan.waivers.alias_resolved",
				"alias", alias,
				"canonical", canonical,
				"hint", "update the waiver rule_id to the canonical name before the alias is removed")
		})
	}

	eng, err := engine.Compile(cat)
	if err != nil {
		var ce *engine.CompileError
		if errors.As(err, &ce) {
			return nil, nil, exit.Catalog("%s", err.Error())
		}
		return nil, nil, exit.Catalog("compiling rules: %s", err)
	}
	return eng, waiverSet, nil
}

// clusterOutcome carries everything one cluster's scan produced. The
// connectErr field captures connect-time failures (transport / auth /
// authz / unknown product) so the multi-cluster path can render a
// per-target error block instead of bailing the whole fleet scan.
// Single-cluster callers handle connectErr by propagating it directly,
// preserving today's exit-code semantics.
type clusterOutcome struct {
	Label      string
	Header     report.Header
	Results    []engine.RuleResult
	connectErr error
}

// scanOneCluster runs the per-cluster part of a scan: connect, fetch
// the health summary, prefetch every applicable probe, evaluate the
// engine against the cache, apply waivers, and build the report
// header. It does not render — the caller decides whether the output
// is single-cluster (existing behaviour) or one block in a
// multi-cluster report.
//
// The engine is reused across calls; nothing here mutates it.
func scanOneCluster(ctx context.Context, eng *engine.Engine, waiverSet *waivers.Set, target targetSpec) clusterOutcome {
	out := clusterOutcome{Label: target.Label}

	// scanStart is the operator-facing "when the scan ran" timestamp:
	// the moment we begin reaching out to the cluster. The Duration
	// field below covers only the engine phase (prefetch + evaluate)
	// because that's the cost-relevant number for catalog-growth
	// triage; CLI startup and connect are bounded by other timeouts.
	scanStart := time.Now()

	logging.Logger().Info("doctor.scan.connect",
		"target", target.Label,
		"addresses", target.Context.Addresses())
	cl, err := connectFn(ctx, target.Context)
	if err != nil {
		out.connectErr = err
		return out
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
		logging.Logger().Debug("doctor.scan.health_summary.failed",
			"target", target.Label, "err", healthErr)
	}

	evalStart := time.Now()
	// Pre-fetch every applicable probe in parallel so the engine can
	// evaluate from cache rather than serialise round trips. Bounded
	// concurrency (DefaultPrefetchConcurrency, currently 4) keeps the
	// cluster from being hit too hard on slow links.
	cache := eng.Prefetch(ctx, registry, dialect, 0)
	results := eng.EvaluateWithCache(ctx, registry, dialect, cache)
	duration := time.Since(evalStart)

	// Annotate findings with operator-supplied waivers before the
	// report renders or the exit-code gate runs. Active suppressions
	// drop out of MaxFailingSeverity / fail-on; expired ones stay
	// loud — the suppression cannot rot silently.
	if !waiverSet.Empty() {
		waiverSet.Apply(scanStart, results)
		logging.Logger().Info("doctor.scan.waivers.applied",
			"target", target.Label,
			"count", waivers.AppliedCount(results),
			"source", waiverSet.Source())
	}

	logRuleTimings(results)

	out.Header = report.Header{
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
	out.Results = results
	return out
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

// applyProfile narrows and severity-overrides cat per the --profile
// flag. Returns cat unchanged when no profile was selected. Loading or
// looking up an unknown profile is a usage error (exit 2) — operators
// see the available profile names in the message.
//
// Two correctness signals get emitted before returning:
//
//   - severity_overrides referencing rule IDs not in the catalog warn
//     loud. A typo'd id silently no-ops at scan time otherwise, which
//     can mean the rule ran with its default (lower) severity for
//     months without anyone noticing.
//   - A profile that filters down to zero rules warns at warn level.
//     The scan continues so an operator developing a profile against
//     a small catalog sees the empty result, but the message tells
//     them the include_tags / rule_ids / skip_tags combo bit them.
func applyProfile(cmd *cli.Command, cat *rules.Catalog) (*rules.Catalog, error) {
	name := strings.TrimSpace(cmd.String("profile"))
	if name == "" {
		return cat, nil
	}
	pcat, err := profiles.LoadEmbedded()
	if err != nil {
		return nil, exit.Catalog("loading profiles: %s", err)
	}
	prof, err := pcat.Get(name)
	if err != nil {
		return nil, exit.Usage("%s", err.Error())
	}
	if unknown := prof.UnknownSeverityOverrides(cat); len(unknown) > 0 {
		logging.Logger().Warn("doctor.scan.profile.unknown_severity_overrides",
			"profile", prof.Name,
			"rule_ids", unknown,
			"hint", "fix the rule_id or remove the override; the entry is currently a no-op")
	}
	out := prof.Apply(cat)
	logging.Logger().Info("doctor.scan.profile.applied",
		"profile", prof.Name,
		"rules_in", len(cat.Rules),
		"rules_out", len(out.Rules))
	if len(out.Rules) == 0 {
		logging.Logger().Warn("doctor.scan.profile.zero_rules_selected",
			"profile", prof.Name,
			"hint", "check include_tags / rule_ids / skip_tags — no rule survives the filter")
	}
	return out, nil
}

// aliasIndex builds a `deprecated_alias → canonical_id` map from the
// catalog. Used by the cli to remap operator waivers keyed by an
// older rule name; the alias-resolution itself lives in the waivers
// package, this just lifts the join out of the rules package which
// has no business knowing about waivers.
func aliasIndex(cat *rules.Catalog) map[string]string {
	if cat == nil || len(cat.Rules) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, r := range cat.Rules {
		for _, alias := range r.DeprecatedAliases {
			if alias == "" || alias == r.ID {
				continue
			}
			out[alias] = r.ID
		}
	}
	return out
}

// loadWaivers resolves the --waivers flag (or the documented default
// search path) and returns the parsed Set. A missing default file is
// silent — "no waivers" is the common state. A missing explicit
// --waivers PATH is a usage error (exit 2): an operator who typed a
// path expects it to exist.
func loadWaivers(cmd *cli.Command) (*waivers.Set, error) {
	if path := cmd.String("waivers"); path != "" {
		set, err := waivers.Load(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, exit.Usage("%s", err.Error())
			}
			return nil, exit.Catalog("%s", err.Error())
		}
		return set, nil
	}
	set, err := waivers.LoadDefault()
	if err != nil {
		return nil, exit.Catalog("%s", err.Error())
	}
	return set, nil
}

// applyScanFilters narrows cat by --rule-id / --tags / --skip-tags.
// Runs after applyProfile so the flags layer onto the profile-selected
// subset; an operator who picks `--profile prod --tags performance`
// gets the intersection. Unknown rule IDs and tags warn loud — a
// typo'd `--rule-id heeap_size` would otherwise silently filter to
// zero rules and pass the gate.
func applyScanFilters(cmd *cli.Command, cat *rules.Catalog) *rules.Catalog {
	filter := catalogFilter{
		RuleIDs:     cmd.StringSlice("rule-id"),
		IncludeTags: cmd.StringSlice("tags"),
		SkipTags:    cmd.StringSlice("skip-tags"),
	}
	if filter.IsEmpty() {
		return cat
	}
	out, unknown := applyCatalogFilter(cat, filter)
	if len(unknown) > 0 {
		logging.Logger().Warn("doctor.scan.filter.unknown_selectors",
			"selectors", unknown,
			"hint", "fix the typo or remove the selector; the entry currently excludes nothing")
	}
	logging.Logger().Info("doctor.scan.filter.applied",
		"rule_ids", filter.RuleIDs,
		"tags", filter.IncludeTags,
		"skip_tags", filter.SkipTags,
		"rules_in", len(cat.Rules),
		"rules_out", len(out.Rules))
	if len(out.Rules) == 0 {
		logging.Logger().Warn("doctor.scan.filter.zero_rules_selected",
			"hint", "check --rule-id / --tags / --skip-tags — no rule survives the filter")
	}
	return out
}
