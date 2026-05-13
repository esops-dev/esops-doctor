package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/urfave/cli/v3"
	yaml "go.yaml.in/yaml/v3"

	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/exit"
	"github.com/esops-dev/esops-doctor/internal/logging"
	"github.com/esops-dev/esops-doctor/internal/probes"
)

// probeCommand prints the raw shape one named probe returns against
// the configured cluster. Authoring a CEL condition against an unfamiliar
// probe shape used to require print-debugging the engine — this surfaces
// the data directly so a rule author can write `self.all(node, ...)`
// after seeing what's in `self`.
//
// No rule evaluation, no scan-gate semantics. The output is the raw
// probe data: useful for piping into jq / yq while iterating on a
// rule's condition.
func probeCommand() *cli.Command {
	return &cli.Command{
		Name:      "probe",
		Usage:     "Print the raw shape a probe returns against the configured cluster",
		ArgsUsage: "NAME",
		Description: "Connects to the cluster (same resolution as scan: --context / --url),\n" +
			"dispatches the named probe, and prints whatever the read-only adapter\n" +
			"returned. Useful when authoring a rule: see the shape `self` will\n" +
			"carry without running the whole catalog.\n\n" +
			"Pass the probe name on the command line; run `esops-doctor probe`\n" +
			"with no argument to see the registered names.",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runProbe(ctx, cmd, cmdWriter(cmd))
		},
	}
}

func runProbe(ctx context.Context, cmd *cli.Command, stdout io.Writer) error {
	if cmd.NArg() == 0 {
		return listKnownProbes(stdout)
	}
	if cmd.NArg() > 1 {
		return exit.Usage("probe accepts exactly one NAME argument; got %d (separate runs for multiple probes)", cmd.NArg())
	}
	name := strings.TrimSpace(cmd.Args().First())
	if name == "" {
		return exit.Usage("probe requires a non-empty NAME argument; run `esops-doctor probe` with no arg to list registered probes")
	}
	if !probes.IsKnown(name) {
		return exit.Usage("unknown probe %q (run `esops-doctor probe` to see the registered names)", name)
	}

	format, err := resolveProbeFormat(ctx, cmd)
	if err != nil {
		return err
	}

	ctxCfg, err := resolveTargetContext(cmd)
	if err != nil {
		return err
	}

	logging.Logger().Info("doctor.probe.connect",
		"target", ctxCfg.URL,
		"probe", name)
	cl, err := connectFn(ctx, ctxCfg)
	if err != nil {
		return err
	}

	registry := probes.New(cl)
	data, err := registry.Probe(ctx, name)
	if err != nil {
		// engine.ErrProbeNotApplicable and ErrProbeNotFound are
		// informational rather than runtime errors — surface them as
		// usage hints so the operator sees a clean message instead of
		// a wrapped sentinel chain.
		if errors.Is(err, engine.ErrProbeNotFound) {
			return exit.Usage("probe %q is not available on this cluster: %s", name, err.Error())
		}
		if errors.Is(err, engine.ErrProbeNotApplicable) {
			return exit.Usage("probe %q is not applicable to this dialect: %s", name, err.Error())
		}
		return fmt.Errorf("probe %q: %w", name, err)
	}

	return renderProbeData(stdout, name, data, format)
}

// resolveProbeFormat picks the wire format for probe NAME. json is the
// default (CEL operates on JSON-shaped data; jq/yq pipelines are what
// rule authors reach for); yaml is the script-friendly alternative.
// table doesn't fit a probe's heterogeneous shape; sarif/junit/html
// are scan-specific.
func resolveProbeFormat(ctx context.Context, cmd *cli.Command) (string, error) {
	picked := strings.TrimSpace(cmd.String("output"))
	if picked == "" {
		picked = defaultsFrom(ctx).Output
	}
	switch strings.ToLower(picked) {
	case "", "json", "table":
		// table falls through to json: a probe with deeply nested
		// shape is not a table. Treating an unset --output as json
		// means rule authors don't have to flag-flip on every run.
		return "json", nil
	case "yaml", "yml":
		return "yaml", nil
	}
	return "", exit.Usage("--output %q is not supported for probe (accepted: json, yaml)", picked)
}

func renderProbeData(w io.Writer, name string, data any, format string) error {
	wrapped := map[string]any{
		"probe": name,
		"data":  data,
	}
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(wrapped)
	case "yaml":
		enc := yaml.NewEncoder(w)
		enc.SetIndent(2)
		defer func() { _ = enc.Close() }()
		return enc.Encode(wrapped)
	default:
		return exit.Usage("--output %q is not supported for probe (accepted: json, yaml)", format)
	}
}

// listKnownProbes is the no-arg fallback: print the registered probe
// names so an operator can discover what they can pass. Sorted for
// stable output.
func listKnownProbes(w io.Writer) error {
	names := probes.Known()
	sort.Strings(names)
	if _, err := fmt.Fprintln(w, "Registered probes:"); err != nil {
		return err
	}
	for _, n := range names {
		if _, err := fmt.Fprintf(w, "  %s\n", n); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "\nRun `esops-doctor probe NAME` to print one probe's raw shape.\n"); err != nil {
		return err
	}
	return nil
}
