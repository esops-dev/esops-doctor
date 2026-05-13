package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/urfave/cli/v3"
	yaml "go.yaml.in/yaml/v3"

	esopsconfig "github.com/esops-dev/esops-go/pkg/config"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

// configShowCommand is the operator-facing "which context is doctor
// actually using?" surface. Unlike `config view` (which renders the
// file as-is), `config show` resolves the full lookup chain and
// prints the answer:
//
//   - config file path actually loaded
//   - current context (after --context override)
//   - effective output / log defaults (after --output etc. overrides)
//   - the full context list with one-line summaries
//
// Secrets are redacted; indirection refs are preserved so the operator
// can verify where a credential lives. There is no --show-secrets opt-
// in by design — diagnostic tooling never resolves credentials.
func configShowCommand() *cli.Command {
	return &cli.Command{
		Name:  "show",
		Usage: "Print the resolved config (paths, context list, current context, effective defaults)",
		Description: "Resolves the same config file the next scan would use, applies\n" +
			"--context / --output / --log-level / --log-format overrides, and\n" +
			"prints the result. Secrets are redacted; ${env:VAR} / ${file:PATH}\n" +
			"/ ${keyring:KEY} refs are preserved so an operator can verify\n" +
			"where a credential lives without doctor revealing it.\n\n" +
			"Use `config view` to dump the file shape verbatim (single context\n" +
			"by default; --all for every context). Use `config show` when the\n" +
			"question is \"what is doctor about to do?\".",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runConfigShow(ctx, cmd, cmdWriter(cmd))
		},
	}
}

// resolvedConfig is the wire shape of `config show`. Fields mirror the
// names operators read in --help and the on-disk YAML, so the text
// output and the json/yaml output stay paste-compatible mental models.
type resolvedConfig struct {
	ConfigFile      string                    `json:"config_file,omitempty" yaml:"config_file,omitempty"`
	CurrentContext  string                    `json:"current_context,omitempty" yaml:"current_context,omitempty"`
	ContextSource   string                    `json:"current_context_source,omitempty" yaml:"current_context_source,omitempty"`
	Defaults        resolvedDefaults          `json:"defaults" yaml:"defaults"`
	Contexts        []resolvedContextSummary  `json:"contexts" yaml:"contexts"`
	SelectedAuth    *resolvedContextSelection `json:"selected_context,omitempty" yaml:"selected_context,omitempty"`
	ResolutionError string                    `json:"resolution_error,omitempty" yaml:"resolution_error,omitempty"`
}

type resolvedDefaults struct {
	Output    string `json:"output,omitempty" yaml:"output,omitempty"`
	LogLevel  string `json:"log_level,omitempty" yaml:"log_level,omitempty"`
	LogFormat string `json:"log_format,omitempty" yaml:"log_format,omitempty"`
	LogFile   string `json:"log_file,omitempty" yaml:"log_file,omitempty"`
}

type resolvedContextSummary struct {
	Name       string `json:"name" yaml:"name"`
	URL        string `json:"url,omitempty" yaml:"url,omitempty"`
	AuthType   string `json:"auth_type,omitempty" yaml:"auth_type,omitempty"`
	Protection string `json:"protection,omitempty" yaml:"protection,omitempty"`
	Current    bool   `json:"current,omitempty" yaml:"current,omitempty"`
}

type resolvedContextSelection struct {
	Name string `json:"name" yaml:"name"`
	URL  string `json:"url,omitempty" yaml:"url,omitempty"`
}

func runConfigShow(ctx context.Context, cmd *cli.Command, stdout io.Writer) error {
	format, err := resolveShowFormat(ctx, cmd)
	if err != nil {
		return err
	}

	// LoadDefault returns the resolved path so the operator can see
	// exactly which file doctor is reading; ESOPS_CONFIG, --config,
	// or the XDG search are all collapsed into one answer here.
	cfg, path, err := esopsconfig.LoadDefault(cmd.String("config"))
	if err != nil {
		return err
	}

	doc := buildResolvedConfig(ctx, cmd, cfg, path)
	return renderResolvedConfig(stdout, doc, format)
}

// resolveShowFormat picks the output format for config show. text is
// the default (a man-page-shaped block); yaml and json round-trip the
// same data structure for scripting. table / sarif / junit / html are
// scan-specific shapes and rejected loudly.
func resolveShowFormat(ctx context.Context, cmd *cli.Command) (string, error) {
	picked := strings.TrimSpace(cmd.String("output"))
	if picked == "" {
		picked = defaultsFrom(ctx).Output
	}
	switch strings.ToLower(picked) {
	case "", "text", "table":
		// table doesn't fit a nested heterogeneous document; fall
		// through to text so an operator with `defaults.output:
		// table` set can still run `config show` without a flag.
		return "text", nil
	case "yaml", "yml":
		return "yaml", nil
	case "json":
		return "json", nil
	}
	return "", exit.Usage("--output %q is not supported for config show (accepted: text, yaml, json)", picked)
}

// buildResolvedConfig assembles the doc shape. Threading runs through:
//
//   - configFile: the path LoadDefault settled on.
//   - currentContext / contextSource: which context the next scan
//     uses, and whether the choice came from --context, the
//     file's current-context, or fell back to a single defined
//     context.
//   - defaults: post-override (--output / --log-*).
//   - contexts: every defined context with a one-line summary.
//   - selectedAuth: a hint at "this is the URL doctor will hit" so
//     a multi-context file's answer is unambiguous.
func buildResolvedConfig(ctx context.Context, cmd *cli.Command, cfg esopsconfig.Config, path string) resolvedConfig {
	defaults := defaultsFrom(ctx)
	doc := resolvedConfig{
		ConfigFile:     path,
		CurrentContext: cfg.CurrentContext,
		Defaults: resolvedDefaults{
			Output:    resolveSetting(cmd, "output", defaults.Output, "table"),
			LogLevel:  resolveLogLevel(cmd, defaults.LogLevel),
			LogFormat: resolveSetting(cmd, "log-format", defaults.LogFormat, defaultLogFormat()),
			LogFile:   resolveSetting(cmd, "log-file", defaults.LogFile, ""),
		},
	}

	requested := strings.TrimSpace(cmd.String("context"))
	switch {
	case requested != "":
		doc.ContextSource = "--context flag"
	case cfg.CurrentContext != "":
		doc.ContextSource = "current-context in " + path
	default:
		doc.ContextSource = "unresolved (no --context, no current-context)"
	}

	names := make([]string, 0, len(cfg.Contexts))
	for name := range cfg.Contexts {
		names = append(names, name)
	}
	sort.Strings(names)
	selectedName := requested
	if selectedName == "" {
		selectedName = cfg.CurrentContext
	}
	for _, name := range names {
		c := cfg.Contexts[name]
		doc.Contexts = append(doc.Contexts, resolvedContextSummary{
			Name:       name,
			URL:        c.URL,
			AuthType:   c.Auth.Type,
			Protection: c.Protection,
			Current:    name == selectedName,
		})
	}

	// Best-effort: ResolveContext applies the same resolution rules
	// the next scan will. Any failure (unset env secret, missing
	// context) is shown inline so the operator knows what's broken
	// without re-running scan. We do not return the error: config
	// show's mandate is "print what we know".
	if name, c, err := cfg.ResolveContext(requested); err == nil {
		doc.SelectedAuth = &resolvedContextSelection{Name: name, URL: c.URL}
	} else {
		doc.ResolutionError = err.Error()
	}
	return doc
}

func renderResolvedConfig(w io.Writer, doc resolvedConfig, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(doc)
	case "yaml":
		enc := yaml.NewEncoder(w)
		enc.SetIndent(2)
		defer func() { _ = enc.Close() }()
		return enc.Encode(doc)
	case "text":
		return renderResolvedConfigText(w, doc)
	default:
		return exit.Usage("--output %q is not supported for config show (accepted: text, yaml, json)", format)
	}
}

// renderResolvedConfigText emits a man-page-shaped block: header,
// then named sections. The shape matches `explain` so an operator
// muscle-memorising one inherits the other.
//
// Writes accumulate into a strings.Builder so the function can decide
// the whole-block output before touching the operator's writer; the
// only I/O is the final io.WriteString. Builder writes never fail, so
// dropping the error returns from intermediate fmt.Fprintf calls is
// safe (and the linter knows it because the final Builder->Writer
// hop is the one that surfaces an error).
func renderResolvedConfigText(w io.Writer, doc resolvedConfig) error {
	var b strings.Builder
	b.WriteString("Resolved configuration\n")
	if doc.ConfigFile != "" {
		b.WriteString("  config_file:     " + doc.ConfigFile + "\n")
	} else {
		b.WriteString("  config_file:     (none — using built-in defaults)\n")
	}
	if doc.CurrentContext != "" {
		if _, err := fmt.Fprintf(&b, "  current_context: %s (source: %s)\n", doc.CurrentContext, doc.ContextSource); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(&b, "  current_context: (unset; source: %s)\n", doc.ContextSource); err != nil {
			return err
		}
	}
	if doc.SelectedAuth != nil {
		if _, err := fmt.Fprintf(&b, "  selected:        %s -> %s\n", doc.SelectedAuth.Name, doc.SelectedAuth.URL); err != nil {
			return err
		}
	}
	if doc.ResolutionError != "" {
		if _, err := fmt.Fprintf(&b, "  resolution_error: %s\n", doc.ResolutionError); err != nil {
			return err
		}
	}

	b.WriteString("\nDefaults:\n")
	dTabs := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	for _, row := range []struct{ k, v string }{
		{"output", orDash(doc.Defaults.Output)},
		{"log_level", orDash(doc.Defaults.LogLevel)},
		{"log_format", orDash(doc.Defaults.LogFormat)},
		{"log_file", orDash(doc.Defaults.LogFile)},
	} {
		if _, err := fmt.Fprintf(dTabs, "  %s\t%s\n", row.k, row.v); err != nil {
			return err
		}
	}
	if err := dTabs.Flush(); err != nil {
		return err
	}

	if len(doc.Contexts) == 0 {
		b.WriteString("\nContexts: (none defined)\n")
	} else {
		if _, err := fmt.Fprintf(&b, "\nContexts (%d):\n", len(doc.Contexts)); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		if _, err := fmt.Fprintln(tw, "  NAME\tURL\tAUTH\tPROTECTION\tCURRENT"); err != nil {
			return err
		}
		for _, c := range doc.Contexts {
			marker := ""
			if c.Current {
				marker = "*"
			}
			if _, err := fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
				c.Name, orDash(c.URL), orDash(c.AuthType), orDash(c.Protection), marker); err != nil {
				return err
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// orDash renders empty strings as "-" so the text-format table reads
// uniformly. Avoids printing a row that looks like every column past
// the first is blank.
func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
