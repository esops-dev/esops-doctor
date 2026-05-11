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

// contextEntry is the render-friendly projection of a context. Field
// order matches the table column order so json/yaml output stays
// visually aligned with the table view.
type contextEntry struct {
	Name        string   `json:"name" yaml:"name"`
	Current     bool     `json:"current" yaml:"current"`
	URL         string   `json:"url,omitempty" yaml:"url,omitempty"`
	URLs        []string `json:"urls,omitempty" yaml:"urls,omitempty"`
	AuthType    string   `json:"auth_type,omitempty" yaml:"auth_type,omitempty"`
	Protection  string   `json:"protection,omitempty" yaml:"protection,omitempty"`
	MaxInFlight int      `json:"max_in_flight,omitempty" yaml:"max_in_flight,omitempty"`
	TLSInsecure bool     `json:"tls_insecure,omitempty" yaml:"tls_insecure,omitempty"`
	CACert      string   `json:"cacert,omitempty" yaml:"cacert,omitempty"`
}

func getContextsCommand() *cli.Command {
	return &cli.Command{
		Name:  "get-contexts",
		Usage: "List configured clusters",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runGetContexts(ctx, cmd, cmdWriter(cmd))
		},
	}
}

func runGetContexts(ctx context.Context, cmd *cli.Command, stdout io.Writer) error {
	cfg, _, err := esopsconfig.LoadDefault(cmd.String("config"))
	if err != nil {
		return err
	}

	format, err := resolveContextListFormat(ctx, cmd)
	if err != nil {
		return err
	}

	return renderContexts(stdout, buildContextEntries(cfg), format)
}

// resolveContextListFormat constrains the global --output to formats
// that make sense for a tabular listing. sarif / junit / html are
// scan-specific report shapes and would render nonsense for a
// context list, so the command rejects them with exit 2 rather than
// silently falling back to table.
func resolveContextListFormat(ctx context.Context, cmd *cli.Command) (string, error) {
	defaults := defaultsFrom(ctx)
	picked := resolveSetting(cmd, "output", defaults.Output, "table")
	switch strings.ToLower(picked) {
	case "table", "json", "yaml":
		return strings.ToLower(picked), nil
	}
	return "", exit.Usage("--output %q is not supported for config get-contexts (accepted: table, json, yaml)", picked)
}

func buildContextEntries(cfg esopsconfig.Config) []contextEntry {
	names := make([]string, 0, len(cfg.Contexts))
	for n := range cfg.Contexts {
		names = append(names, n)
	}
	sort.Strings(names)

	entries := make([]contextEntry, 0, len(names))
	for _, n := range names {
		c := cfg.Contexts[n]
		entries = append(entries, contextEntry{
			Name:        n,
			Current:     n == cfg.CurrentContext,
			URL:         c.URL,
			URLs:        append([]string(nil), c.URLs...),
			AuthType:    c.Auth.Type,
			Protection:  c.Protection,
			MaxInFlight: c.MaxInFlight,
			TLSInsecure: c.TLS.Insecure,
			CACert:      c.TLS.CACert,
		})
	}
	return entries
}

func renderContexts(w io.Writer, entries []contextEntry, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	case "yaml":
		enc := yaml.NewEncoder(w)
		enc.SetIndent(2)
		defer func() { _ = enc.Close() }()
		return enc.Encode(entries)
	case "table", "":
		return renderContextTable(w, entries)
	default:
		return exit.Usage("--output %q is not supported for config get-contexts (accepted: table, json, yaml)", format)
	}
}

func renderContextTable(w io.Writer, entries []contextEntry) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "CURRENT\tNAME\tURL\tAUTH\tPROTECTION"); err != nil {
		return err
	}
	for _, e := range entries {
		marker := ""
		if e.Current {
			marker = "*"
		}
		url := e.URL
		if url == "" && len(e.URLs) > 0 {
			url = e.URLs[0]
		}
		authType := e.AuthType
		if authType == "" {
			authType = "none"
		}
		prot := e.Protection
		if prot == "" {
			prot = "none"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", marker, e.Name, url, authType, prot); err != nil {
			return err
		}
	}
	return tw.Flush()
}
