package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/urfave/cli/v3"

	esopsconfig "github.com/esops-dev/esops-go/pkg/config"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

// Context-not-found is treated as a usage error (exit 2) rather than
// a generic failure (exit 1): the user typed a name that doesn't
// match anything in the config file, the same way a flag with an
// invalid value would be rejected. CI scripts can rely on the exit
// code to tell "operator typo" apart from "doctor broke".

func useContextCommand() *cli.Command {
	return &cli.Command{
		Name:      "use-context",
		Usage:     "Set the default context (writes to the config file)",
		ArgsUsage: "NAME",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runUseContext(ctx, cmd, cmdWriter(cmd))
		},
		ShellComplete: completeContextNames,
	}
}

// completeContextNames prints known contexts from the loaded config,
// one per line, for shell tab-completion. Errors are swallowed — a
// failed lookup during completion should silently offer nothing rather
// than spew diagnostics into the user's shell.
func completeContextNames(_ context.Context, cmd *cli.Command) {
	if cmd.NArg() > 0 {
		return
	}
	cfg, _, err := esopsconfig.LoadDefault(cmd.String("config"))
	if err != nil {
		return
	}
	for _, name := range sortedContextNames(cfg.Contexts) {
		_, _ = fmt.Fprintln(cmd.Writer, name)
	}
}

func runUseContext(_ context.Context, cmd *cli.Command, stdout io.Writer) error {
	args := cmd.Args()
	if args.Len() != 1 {
		return exit.Usage("expected 1 argument (context name), got %d", args.Len())
	}
	name := args.First()

	cfg, path, err := esopsconfig.LoadDefault(cmd.String("config"))
	if err != nil {
		return err
	}
	if _, ok := cfg.Contexts[name]; !ok {
		return exit.Usage("context %q not found in %s (available: %s)",
			name, path, strings.Join(sortedContextNames(cfg.Contexts), ", "))
	}
	if name == cfg.CurrentContext {
		_, err := fmt.Fprintf(stdout, "Already on context %q.\n", name)
		return err
	}
	if err := esopsconfig.SetCurrentContext(path, name); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Switched to context %q.\n", name)
	return err
}

func sortedContextNames(m map[string]esopsconfig.Context) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
