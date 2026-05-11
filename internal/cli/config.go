package cli

import (
	"github.com/urfave/cli/v3"
)

// configCommand is the `config` command group: inspect and modify the
// on-disk config file that doctor shares with esops. Mutation is
// limited to the current-context pointer (the only knob `use-context`
// turns); the rest of the file is read-only territory, edited by the
// operator.
func configCommand() *cli.Command {
	return &cli.Command{
		Name:  "config",
		Usage: "Inspect and modify esops configuration",
		Description: "Operates on the same file as esops (~/.config/esops/config.yaml or\n" +
			"$ESOPS_CONFIG). Only `use-context` writes to the file; the other\n" +
			"subcommands are read-only.",
		Commands: []*cli.Command{
			getContextsCommand(),
			useContextCommand(),
			configViewCommand(),
		},
	}
}
