package cli

// Shell completion rendering. urfave/cli/v3 auto-registers a hidden
// `completion` command when EnableShellCompletion is set; doctor
// replaces the default action because v3.8.0's fish template is
// rendered via fmt.Sprintf with a verb the formatter cannot parse,
// producing a script full of %!(MISSING) tokens.
//
// The four templates are MIT-licensed and originate upstream
// (github.com/urfave/cli). They live under completion_templates/ and
// substitute {{APP}} via plain string replacement so no fmt verb is
// involved.

import (
	"context"
	_ "embed"
	"fmt"
	"sort"
	"strings"

	"github.com/esops-dev/esops-doctor/internal/exit"
	"github.com/urfave/cli/v3"
)

//go:embed completion_templates/bash
var bashCompletionScript string

//go:embed completion_templates/zsh
var zshCompletionScript string

//go:embed completion_templates/fish
var fishCompletionScript string

//go:embed completion_templates/pwsh
var pwshCompletionScript string

var completionScripts = map[string]string{
	"bash": bashCompletionScript,
	"zsh":  zshCompletionScript,
	"fish": fishCompletionScript,
	"pwsh": pwshCompletionScript,
}

const completionDescription = `Output a shell completion script for bash, zsh, fish, or PowerShell.

Source the output to enable completion. Examples:

  # bash
  source <(esops-doctor completion bash)

  # zsh
  source <(esops-doctor completion zsh)

  # fish
  esops-doctor completion fish > ~/.config/fish/completions/esops-doctor.fish

  # PowerShell
  esops-doctor completion pwsh > esops-doctor.ps1

Package installers (deb, rpm, Homebrew) ship pre-rendered scripts from
the completions/ directory, so this subcommand is primarily for source
builds and interactive use.`

// configureCompletion mutates the auto-registered completion command
// in place: un-hides it, swaps in a friendlier description, and
// overrides the action so fish renders correctly. Wired into the
// root command via ConfigureShellCompletionCommand.
func configureCompletion(c *cli.Command) {
	c.Hidden = false
	c.Description = completionDescription
	c.Action = completionAction
}

func completionAction(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() == 0 {
		return exit.Usage("no shell provided; available: %s", completionShellList())
	}
	shell := cmd.Args().First()
	tmpl, ok := completionScripts[shell]
	if !ok {
		return exit.Usage("unknown shell %q; available: %s", shell, completionShellList())
	}
	// Route through cmdWriter so tests that swap root.Writer capture
	// the output. urfave/cli does not propagate Writer to subcommands
	// automatically; cmd.Writer here is the per-subcommand sink.
	_, err := fmt.Fprint(cmdWriter(cmd), renderCompletion(tmpl, cmd.Root().Name))
	return err
}

// renderCompletion substitutes the app name placeholder. Exported as a
// helper for tests and reused by the action.
func renderCompletion(tmpl, appName string) string {
	return strings.ReplaceAll(tmpl, "{{APP}}", appName)
}

func completionShellList() string {
	names := make([]string, 0, len(completionScripts))
	for k := range completionScripts {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
