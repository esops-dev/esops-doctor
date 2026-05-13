package cli

import (
	"io"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/esops-dev/esops-doctor/internal/report"
)

// resolveColorEnabled projects --no-color plus the standard
// terminal-colour env vars (NO_COLOR, CLICOLOR, CLICOLOR_FORCE) onto
// the report layer's three-way preference and asks the report layer
// for the final yes/no. Lives in cli — not report — because the report
// package has no business reading os.Getenv directly: the cli is the
// boundary that turns operator-supplied environment into a decision.
//
// stdout is the destination the table renderer will write to. When
// it's a non-TTY (a pipe, a file, a tests bytes.Buffer) ColorAuto
// resolves to false; --no-color and NO_COLOR force off regardless;
// CLICOLOR_FORCE forces on regardless.
func resolveColorEnabled(cmd *cli.Command, stdout io.Writer) bool {
	pref := report.ColorAuto
	if cmd.Bool("no-color") {
		pref = report.ColorDisable
	}
	return report.ResolveColorEnabled(pref, stdout, os.Getenv)
}
