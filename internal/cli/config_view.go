package cli

import (
	"context"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/urfave/cli/v3"
	yaml "go.yaml.in/yaml/v3"

	esopsconfig "github.com/esops-dev/esops-go/pkg/config"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

// redactionPlaceholder replaces inline plaintext secrets in the view
// output. Chosen to be visually obvious in both yaml and json output,
// and short enough not to disrupt alignment when an operator eyeballs
// the file. Doctor never renders a literal secret in plain text — the
// placeholder applies unconditionally, by design (no --show-secrets
// opt-in). Operators who need to inspect actual credentials should
// use the upstream `esops` binary directly; doctor's diagnostic
// mandate stops at the credential boundary.
const redactionPlaceholder = "REDACTED"

// secretRefPattern matches ${scheme:arg} indirection. Refs are
// *pointers* to a secret and safe to print verbatim — they tell the
// operator where the credential lives without exposing it. Literal
// secret material falls through to the redaction branch.
var secretRefPattern = regexp.MustCompile(`^\$\{[a-z]+:[^}]+\}$`)

// viewDoc is the render-friendly projection of a Config. Field names
// and casing intentionally mirror the on-disk YAML so the operator's
// `config view` output is paste-compatible back into the file *for
// non-secret fields*. Nested structs are pointers so omitempty elides
// empty blocks (yaml.v3 does not treat zero-value structs as empty).
type viewDoc struct {
	CurrentContext string                 `json:"current-context,omitempty" yaml:"current-context,omitempty"`
	Defaults       *viewDefaults          `json:"defaults,omitempty" yaml:"defaults,omitempty"`
	Contexts       map[string]viewContext `json:"contexts,omitempty" yaml:"contexts,omitempty"`
}

type viewDefaults struct {
	Output     string `json:"output,omitempty" yaml:"output,omitempty"`
	LogLevel   string `json:"log_level,omitempty" yaml:"log_level,omitempty"`
	LogFormat  string `json:"log_format,omitempty" yaml:"log_format,omitempty"`
	LogFile    string `json:"log_file,omitempty" yaml:"log_file,omitempty"`
	Timeout    string `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	MaxRetries int    `json:"max_retries,omitempty" yaml:"max_retries,omitempty"`
	Compress   bool   `json:"compress,omitempty" yaml:"compress,omitempty"`
}

type viewContext struct {
	URL         string    `json:"url,omitempty" yaml:"url,omitempty"`
	URLs        []string  `json:"urls,omitempty" yaml:"urls,omitempty"`
	Auth        *viewAuth `json:"auth,omitempty" yaml:"auth,omitempty"`
	TLS         *viewTLS  `json:"tls,omitempty" yaml:"tls,omitempty"`
	Protection  string    `json:"protection,omitempty" yaml:"protection,omitempty"`
	MaxInFlight int       `json:"max_in_flight,omitempty" yaml:"max_in_flight,omitempty"`
	Timeout     string    `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Compress    bool      `json:"compress,omitempty" yaml:"compress,omitempty"`
}

type viewAuth struct {
	Type       string `json:"type,omitempty" yaml:"type,omitempty"`
	Username   string `json:"username,omitempty" yaml:"username,omitempty"`
	Password   string `json:"password,omitempty" yaml:"password,omitempty"`
	APIKey     string `json:"api_key,omitempty" yaml:"api_key,omitempty"`
	Token      string `json:"token,omitempty" yaml:"token,omitempty"`
	ClientCert string `json:"client_cert,omitempty" yaml:"client_cert,omitempty"`
	ClientKey  string `json:"client_key,omitempty" yaml:"client_key,omitempty"`
	Region     string `json:"region,omitempty" yaml:"region,omitempty"`
	Service    string `json:"service,omitempty" yaml:"service,omitempty"`
}

type viewTLS struct {
	CACert   string `json:"cacert,omitempty" yaml:"cacert,omitempty"`
	Insecure bool   `json:"insecure,omitempty" yaml:"insecure,omitempty"`
}

func configViewCommand() *cli.Command {
	return &cli.Command{
		Name:  "view",
		Usage: "Print the effective config (literal secrets redacted; indirection refs preserved)",
		Description: "Renders the loaded config as YAML (default) or JSON. Inline\n" +
			"secrets (password / api_key / token literals) are always shown\n" +
			"as REDACTED; ${env:VAR} / ${file:PATH} / ${keyring:KEY} refs\n" +
			"are preserved verbatim so an operator can tell where a\n" +
			"credential lives without doctor revealing it. There is no\n" +
			"--show-secrets opt-in by design — diagnostic tooling has no\n" +
			"business resolving credentials.",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "all",
				Usage: "Include every context (default: only the current context)",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runConfigView(ctx, cmd, cmdWriter(cmd))
		},
	}
}

func runConfigView(ctx context.Context, cmd *cli.Command, stdout io.Writer) error {
	cfg, _, err := esopsconfig.LoadDefault(cmd.String("config"))
	if err != nil {
		return err
	}
	format, err := resolveViewFormat(ctx, cmd)
	if err != nil {
		return err
	}
	doc, err := buildViewDoc(cfg, viewOptions{
		all:      cmd.Bool("all"),
		selected: cmd.String("context"),
	})
	if err != nil {
		return err
	}
	return renderView(stdout, doc, format)
}

// viewOptions controls which slice of the config view renders.
// Defaulting to the single current context (rather than the whole
// file) matches the "show me what I'm about to operate against" read
// of `config view`; --all restores the full-file dump for auditing.
type viewOptions struct {
	all bool
	// selected names the context to show. Empty falls back to the
	// file's current-context. Ignored when all is true.
	selected string
}

// resolveViewFormat picks the output format in priority order:
// explicit --output > defaults.output (if it's yaml or json) >
// yaml. defaults.output set to a scan-only format (table, sarif,
// junit, html) does not error here — view falls back to yaml so an
// operator who configured defaults.output for scan reports can still
// view their config without a separate flag.
func resolveViewFormat(ctx context.Context, cmd *cli.Command) (string, error) {
	if explicit := strings.TrimSpace(cmd.String("output")); explicit != "" {
		return parseViewFormat(explicit)
	}
	switch strings.ToLower(strings.TrimSpace(defaultsFrom(ctx).Output)) {
	case "json":
		return "json", nil
	case "yaml", "yml":
		return "yaml", nil
	}
	return "yaml", nil
}

// parseViewFormat is a tighter parser than the global --output set:
// config view targets yaml (matches the on-disk shape) and json (the
// scriptable alternative). table doesn't fit a nested heterogeneous
// document; sarif/junit/html are scan-specific shapes.
func parseViewFormat(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "yaml", "yml":
		return "yaml", nil
	case "json":
		return "json", nil
	default:
		return "", exit.Usage("--output %q is not supported for config view (accepted: yaml, json)", s)
	}
}

// buildViewDoc projects a Config into viewDoc, redacting password /
// api_key / token literals unconditionally. Indirection refs
// (${env:...}, ${file:...}, ${keyring:...}) are preserved as-is —
// they're pointers, not secrets themselves, and hiding them would
// remove information an operator needs to verify config shape.
//
// Context filtering: by default only the selected context
// (opts.selected, falling back to cfg.CurrentContext) is included.
// opts.all restores the full-file dump. A selected name that's absent
// from the file is a usage error — either the operator's --context
// flag or current-context points somewhere broken, and silently
// dropping contexts would mask that.
func buildViewDoc(cfg esopsconfig.Config, opts viewOptions) (viewDoc, error) {
	doc := viewDoc{CurrentContext: cfg.CurrentContext}
	if d := projectDefaults(cfg.Defaults); d != nil {
		doc.Defaults = d
	}

	if opts.all {
		if len(cfg.Contexts) > 0 {
			doc.Contexts = make(map[string]viewContext, len(cfg.Contexts))
			for name, c := range cfg.Contexts {
				doc.Contexts[name] = projectContext(c)
			}
		}
		return doc, nil
	}

	target := opts.selected
	if target == "" {
		target = cfg.CurrentContext
	}
	if target == "" {
		// No current-context and no --context: the "current slice" is
		// empty. Render defaults only; pass --all to see everything.
		return doc, nil
	}
	c, ok := cfg.Contexts[target]
	if !ok {
		return viewDoc{}, exit.Usage("context %q not found in config", target)
	}
	doc.Contexts = map[string]viewContext{target: projectContext(c)}
	return doc, nil
}

func projectDefaults(d esopsconfig.Defaults) *viewDefaults {
	if d == (esopsconfig.Defaults{}) {
		return nil
	}
	return &viewDefaults{
		Output:     d.Output,
		LogLevel:   d.LogLevel,
		LogFormat:  d.LogFormat,
		LogFile:    d.LogFile,
		Timeout:    durationString(d.Timeout),
		MaxRetries: d.MaxRetries,
		Compress:   d.Compress,
	}
}

func projectContext(c esopsconfig.Context) viewContext {
	vc := viewContext{
		URL:         c.URL,
		URLs:        append([]string(nil), c.URLs...),
		Protection:  c.Protection,
		MaxInFlight: c.MaxInFlight,
		Timeout:     durationString(c.Timeout),
		Compress:    c.Compress,
	}
	if a := projectAuth(c.Auth); a != nil {
		vc.Auth = a
	}
	if c.TLS != (esopsconfig.TLS{}) {
		vc.TLS = &viewTLS{CACert: c.TLS.CACert, Insecure: c.TLS.Insecure}
	}
	return vc
}

func projectAuth(a esopsconfig.Auth) *viewAuth {
	if a == (esopsconfig.Auth{}) {
		return nil
	}
	return &viewAuth{
		Type:       a.Type,
		Username:   a.Username,
		Password:   redactLiteral(a.Password),
		APIKey:     redactLiteral(a.APIKey),
		Token:      redactLiteral(a.Token),
		ClientCert: a.ClientCert,
		ClientKey:  a.ClientKey,
		Region:     a.Region,
		Service:    a.Service,
	}
}

// redactLiteral returns s when it's empty (no secret to hide) or an
// indirection ref (a pointer to a secret, not the secret itself);
// otherwise it returns the redaction placeholder. There is no opt-out
// path: doctor never resolves refs to their values, and never prints
// literal secret material.
func redactLiteral(s string) string {
	if s == "" || secretRefPattern.MatchString(s) {
		return s
	}
	return redactionPlaceholder
}

// durationString formats a Duration as "30s"-style text, matching the
// on-disk shape. Zero returns "" so omitempty hides the field.
func durationString(d time.Duration) string {
	if d == 0 {
		return ""
	}
	return d.String()
}

func renderView(w io.Writer, doc viewDoc, format string) error {
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
	default:
		return exit.Usage("--output %q is not supported for config view (accepted: yaml, json)", format)
	}
}
