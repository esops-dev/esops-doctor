package cli

import (
	"strings"

	"github.com/esops-dev/esops-go/pkg/config"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

// targetSpec is one cluster the multi-cluster scan path will visit.
// Label is the operator-facing identifier used in per-cluster output
// blocks and log lines — for context-based targets it's the context
// name. Context carries the resolved cluster connection settings as
// the upstream config layer expects them.
type targetSpec struct {
	Label   string
	Context config.Context
}

// resolveMultiTargets returns the list of clusters the scan command
// should visit when --targets is set, plus a boolean signalling that
// multi-cluster mode is active. Returns (nil, false, nil) when the
// flag is empty so the caller falls through to the single-cluster
// path.
//
// Each entry is a context name; doctor reuses the operator's existing
// esops config (same file the single-cluster --context flag consults)
// so authentication, TLS, and secret indirection come for free. Ad-hoc
// URLs without a matching context are not supported here — define a
// context in the config file, or fall back to a single-shot
// `scan --url` for one-off probes.
//
// Mutual exclusion with --url / --context is enforced loud: an
// operator who set --targets and --url at the same time gets a usage
// error rather than the surprise of one being silently ignored.
func resolveMultiTargets(cmd interface {
	StringSlice(string) []string
	String(string) string
	Bool(string) bool
	IsSet(string) bool
}) ([]targetSpec, bool, error) {
	multi := cmd.StringSlice("targets")
	if len(multi) == 0 {
		return nil, false, nil
	}

	if cmd.String("url") != "" {
		return nil, true, exit.Usage("--url is for single-cluster scans; --targets supersedes it")
	}
	if cmd.String("context") != "" {
		return nil, true, exit.Usage("--context selects a single cluster; --targets supersedes it")
	}

	cfg, _, err := config.LoadDefault(cmd.String("config"))
	if err != nil {
		return nil, true, exit.Usage("loading config for --targets: %s", err.Error())
	}

	tlsOverride := config.TLS{
		CACert:   cmd.String("cacert"),
		Insecure: cmd.Bool("insecure"),
	}
	insecureSet := cmd.IsSet("insecure")
	cacertOverride := cmd.String("cacert")

	out := make([]targetSpec, 0, len(multi))
	seen := make(map[string]struct{}, len(multi))
	for _, raw := range multi {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			// Skipping a duplicate is friendlier than scanning the same
			// cluster twice; an operator who paste-doubled a context
			// name in `--targets prod-eu,prod-eu` gets the cluster
			// scanned once with no surprise. Loud-skip via debug log
			// happens at the call site if we ever need it.
			continue
		}
		seen[name] = struct{}{}

		_, ctx, err := cfg.ResolveContext(name)
		if err != nil {
			return nil, true, exit.Usage("--targets: %s", err.Error())
		}
		if cacertOverride != "" {
			ctx.TLS.CACert = cacertOverride
		}
		if insecureSet {
			ctx.TLS.Insecure = tlsOverride.Insecure
		}
		out = append(out, targetSpec{Label: name, Context: ctx})
	}
	if len(out) == 0 {
		return nil, true, exit.Usage("--targets is empty after trimming whitespace")
	}
	return out, true, nil
}
