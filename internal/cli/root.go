package cli

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/esops-dev/esops-go/pkg/config"

	"github.com/esops-dev/esops-doctor/internal/exit"
	"github.com/esops-dev/esops-doctor/internal/logging"
	"github.com/esops-dev/esops-doctor/internal/version"
)

// Run builds and executes the root command. Errors bubble up to main,
// which maps them to the documented exit codes via exit.Code.
func Run(ctx context.Context, args []string) error {
	return wrapUsageError(newRoot().Run(ctx, args))
}

func newRoot() *cli.Command {
	return &cli.Command{
		Name:    "esops-doctor",
		Usage:   "Read-only diagnostic linter for self-managed Elasticsearch and OpenSearch",
		Version: version.Version,
		Description: "esops-doctor scans a self-managed Elasticsearch or OpenSearch cluster\n" +
			"for known anti-patterns, mis-configurations, and hygiene gaps, and\n" +
			"reports findings with severities and remediation hints.\n\n" +
			"It is read-only by construction: every cluster operation goes through\n" +
			"the read-only capability surface of esops-go. No telemetry of any\n" +
			"kind — outbound connections go only to the cluster URLs you name.\n\n" +
			"Configuration is loaded from the same file as esops\n" +
			"(~/.config/esops/config.yaml or $ESOPS_CONFIG); see the README for the\n" +
			"context shape and a CI gating recipe.",
		// EnableShellCompletion lets the binary respond to
		// --generate-shell-completion when sourced from the bundled
		// scripts under completions/. Operators install the script
		// once (per-shell convention, see CONTRIBUTING.md), and tab-
		// completion thereafter works without doctor learning a
		// dedicated `completion` subcommand.
		EnableShellCompletion: true,
		Flags:                 globalFlags(),
		Before:                initLogger,
		Commands: []*cli.Command{
			scanCommand(),
			listRulesCommand(),
			explainCommand(),
			validateRulesCommand(),
			newProfileCommand(),
			versionCommand(),
		},
	}
}

// globalFlags declares the flags available to every subcommand. Doctor
// reuses esops's config file shape, so --config / --context / --url /
// --cacert / --insecure / --output match the esops surface; --quiet and
// --summary-only are doctor-specific report-shaping flags. --log-file
// mirrors esops so an operator can pin doctor's logs to disk in CI.
func globalFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "config",
			Aliases: []string{"c"},
			Usage:   "Path to YAML config file (overrides ESOPS_CONFIG and the XDG search)",
		},
		&cli.StringFlag{
			Name:    "context",
			Aliases: []string{"cluster"},
			Usage:   "Named cluster from config (overrides current-context)",
		},
		&cli.StringFlag{
			Name:  "url",
			Usage: "Override: single cluster URL (bypasses context lookup)",
		},
		&cli.StringFlag{
			Name:  "cacert",
			Usage: "Custom CA bundle path",
		},
		&cli.BoolFlag{
			Name:  "insecure",
			Usage: "Skip TLS verification (last resort)",
		},
		&cli.StringFlag{
			Name:      "output",
			Aliases:   []string{"o"},
			Usage:     "Output format: table | json | yaml | sarif | junit | html (overrides defaults.output)",
			Validator: validateOutput,
		},
		&cli.BoolFlag{
			Name:  "quiet",
			Usage: "Errors only (shorthand for --log-level error; --log-level wins if set)",
		},
		&cli.BoolFlag{
			Name:  "summary-only",
			Usage: "One-line summary, no per-finding output",
		},
		&cli.StringFlag{
			Name:      "log-level",
			Usage:     "Log level: debug | info | warn | error (overrides defaults.log_level)",
			Validator: validateLogLevel,
		},
		&cli.StringFlag{
			Name:      "log-format",
			Usage:     "Log format: text | json (overrides defaults.log_format; auto-json under CI=true)",
			Validator: validateLogFormat,
		},
		&cli.StringFlag{
			Name:  "log-file",
			Usage: "Append log lines to PATH instead of stderr (file created with mode 0600; overrides defaults.log_file)",
		},
	}
}

// implementedOutputFormats lists the formats the report layer can
// actually render today. Add a name here once a renderer lands; until
// then, passing the format value would silently fall through to a
// table — and "scriptable" formats must be honoured exactly. Better
// to reject loudly with exit 2.
var implementedOutputFormats = []string{"table", "json", "yaml", "sarif", "junit", "html"}

// plannedOutputFormats lists formats the project promises but that
// have not landed yet. Listed separately so the error message tells
// the operator the format is *known* but not yet wired, rather than
// rejected as a typo. Empty for now: every promised format is wired.
var plannedOutputFormats = []string{}

func validateOutput(s string) error {
	if s == "" {
		return nil
	}
	for _, v := range implementedOutputFormats {
		if strings.EqualFold(s, v) {
			return nil
		}
	}
	for _, v := range plannedOutputFormats {
		if strings.EqualFold(s, v) {
			return exit.Usage("--output %q is documented but not yet implemented; only %s is wired today",
				s, strings.Join(implementedOutputFormats, ", "))
		}
	}
	return exit.Usage("--output %q is not supported (accepted: %s)",
		s, strings.Join(implementedOutputFormats, ", "))
}

func validateLogLevel(s string) error {
	if logging.ValidLevel(s) {
		return nil
	}
	return exit.Usage("--log-level %q is not supported (accepted: debug, info, warn, error)", s)
}

func validateLogFormat(s string) error {
	if logging.ValidFormat(s) {
		return nil
	}
	return exit.Usage("--log-format %q is not supported (accepted: text, json)", s)
}

// initLogger is the root Before hook: configures slog from flag values,
// falling back to config.Defaults and finally to the flag's built-in
// default. Runs once so every subcommand observes the same logger.
//
// Config load is best-effort: if no config is found the command may still
// be useful (e.g. `esops-doctor version`, `esops-doctor --help`), so we
// don't fail here. logging.Init failures wrap as usage errors — a bad
// --log-file path or a value that slipped past the Validator should map
// to exit code 2.
func initLogger(ctx context.Context, cmd *cli.Command) (context.Context, error) {
	defaults := readDefaults(cmd.String("config"))
	// Stash the parsed defaults on ctx so subcommands (runScan) don't
	// re-walk the config search path and re-parse the YAML for their
	// own defaults lookup. Single-shot CLI doesn't need much, but the
	// double-parse showed up under -race and is trivial to avoid.
	ctx = withDefaults(ctx, defaults)
	level := resolveLogLevel(cmd, defaults.LogLevel)
	format := resolveSetting(cmd, "log-format", defaults.LogFormat, defaultLogFormat())
	logFile := resolveSetting(cmd, "log-file", defaults.LogFile, "")
	if err := logging.Init(level, format, logFile); err != nil {
		return ctx, exit.Usage("%s", err.Error())
	}
	logging.Logger().Debug("doctor.start",
		"log_level", level,
		"log_format", format,
		"log_file", logFile,
	)
	return ctx, nil
}

// defaultsKey is the unexported key the Before hook uses to stash the
// parsed config defaults on the context. Subcommands read it via
// defaultsFrom; they never re-parse the file themselves.
type defaultsKey struct{}

func withDefaults(ctx context.Context, d config.Defaults) context.Context {
	return context.WithValue(ctx, defaultsKey{}, d)
}

// defaultsFrom returns the config defaults the Before hook stashed on
// ctx. Falls back to a zero Defaults when nothing was stashed (so
// callers that build a Command without going through Run still work).
func defaultsFrom(ctx context.Context) config.Defaults {
	if d, ok := ctx.Value(defaultsKey{}).(config.Defaults); ok {
		return d
	}
	return config.Defaults{}
}

// readDefaults loads the config file quietly for the Before hook. Returns
// a zero Defaults on any failure so commands that don't need a config
// (--help, version) still work.
func readDefaults(explicit string) config.Defaults {
	path, err := config.Resolve(explicit)
	if err != nil {
		return config.Defaults{}
	}
	cfg, err := config.Parse(path)
	if err != nil {
		return config.Defaults{}
	}
	return cfg.Defaults
}

// resolveLogLevel picks the log level in priority order: explicit
// --log-level > --quiet > config defaults > built-in default. --quiet is
// a shorthand operators expect; an explicit --log-level wins because the
// principle is "the flag the user typed beats the flag they implied".
//
// On stdout, --quiet additionally drops the per-skipped section from
// the table report — that wiring lives in cli/scan.go where the flag
// is read and threaded into report.TableOptions.
func resolveLogLevel(cmd *cli.Command, fromConfig string) string {
	if cmd.IsSet("log-level") {
		return cmd.String("log-level")
	}
	if cmd.Bool("quiet") {
		return "error"
	}
	if fromConfig != "" {
		return fromConfig
	}
	return "info"
}

// resolveSetting picks a string setting in priority order: explicit
// flag > config file > built-in default.
func resolveSetting(cmd *cli.Command, flag, fromConfig, builtin string) string {
	if cmd.IsSet(flag) {
		return cmd.String(flag)
	}
	if fromConfig != "" {
		return fromConfig
	}
	return builtin
}

// resolveOutput picks the report format in priority order: explicit
// --output > defaults.output from the config file > "table". The
// resolved value is asserted against implementedOutputFormats so a
// `defaults.output: json` in an operator's config fails loud
// (Milestone-3 message) rather than silently rendering a table.
func resolveOutput(cmd *cli.Command, fromConfig string) (string, error) {
	picked := resolveSetting(cmd, "output", fromConfig, "table")
	for _, v := range implementedOutputFormats {
		if strings.EqualFold(picked, v) {
			return strings.ToLower(picked), nil
		}
	}
	for _, v := range plannedOutputFormats {
		if strings.EqualFold(picked, v) {
			return "", exit.Usage("output %q is documented but not yet implemented; only %s is wired today",
				picked, strings.Join(implementedOutputFormats, ", "))
		}
	}
	return "", exit.Usage("output %q is not supported (accepted: %s)",
		picked, strings.Join(implementedOutputFormats, ", "))
}

// defaultLogFormat returns "json" under CI and "text" otherwise. Used
// when neither the flag nor the config file set a preference.
func defaultLogFormat() string {
	v := os.Getenv("CI")
	if v == "true" || v == "1" {
		return "json"
	}
	return "text"
}

// wrapUsageError maps urfave's flag-validation errors to exit.ErrUsage so
// they exit 2, and marks them silent so main does not
// double-print — urfave already wrote "Incorrect Usage: ..." to stderr by
// the time we see the error. Errors that did NOT come from urfave's flag
// machinery (Before-hook failures, action errors carrying their own
// ErrUsage) pass through and print normally.
//
// urfave's typed errors are unexported, so we match on the well-known
// message prefixes the library emits — a best-effort match.
func wrapUsageError(err error) error {
	if err == nil {
		return nil
	}
	if !isUrfaveFlagError(err.Error()) {
		return err
	}
	if !errors.Is(err, exit.ErrUsage) {
		err = exit.Usage("%s", err.Error())
	}
	return exit.Silent(err)
}

// isUrfaveFlagError reports whether msg matches one of urfave's
// flag-validation error message prefixes — the cases where the library
// has already printed "Incorrect Usage: ..." to stderr.
func isUrfaveFlagError(msg string) bool {
	for _, prefix := range []string{
		"Required flag ",
		"Required flags ",
		"flag provided but not defined",
		"flag needs an argument",
		"option ",
		"one of these flags needs to be provided",
		"invalid value",
	} {
		if strings.Contains(msg, prefix) {
			return true
		}
	}
	return false
}
