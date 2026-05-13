package report

import (
	"io"
	"os"
	"strings"

	"github.com/esops-dev/esops-doctor/internal/findings"
)

// ANSI escape codes for the severity palette. Bold red for critical
// pulls the eye first; the rest follow standard convention. Reset is
// emitted at the end of every coloured token so a captured log file
// keeps the surrounding text uncoloured.
//
// The palette is deliberately small — the table renders one row per
// failing rule and a one-line summary; over-styling would punish a
// noisy day. Severity is the only column that takes colour today.
const (
	ansiReset    = "\x1b[0m"
	ansiCritical = "\x1b[1;31m"
	ansiError    = "\x1b[31m"
	ansiWarn     = "\x1b[33m"
	ansiInfo     = "\x1b[36m"
)

// colorize wraps s in the ANSI escape for sev. enabled=false returns s
// unchanged so a non-TTY consumer or an operator passing --no-color
// sees clean text. Callers pass the operator-resolved decision in
// rather than each reaching for env / TTY state on their own — that's
// the report package's contract with the cli (see ResolveColorEnabled).
func colorize(s string, sev findings.Severity, enabled bool) string {
	if !enabled {
		return s
	}
	switch sev {
	case findings.SeverityCritical:
		return ansiCritical + s + ansiReset
	case findings.SeverityError:
		return ansiError + s + ansiReset
	case findings.SeverityWarn:
		return ansiWarn + s + ansiReset
	case findings.SeverityInfo:
		return ansiInfo + s + ansiReset
	default:
		return s
	}
}

// ColorPreference is the operator-supplied --no-color flag projection.
// Three-valued so we can distinguish "user typed --no-color" (Disable)
// from "user said nothing" (Auto) and from a forced enable (Enable),
// which currently has no user-facing flag but exists so the env-var
// CLICOLOR_FORCE branch has a well-typed home.
type ColorPreference int

const (
	// ColorAuto resolves at runtime: enable when stdout is a TTY and
	// no NO_COLOR / CLICOLOR=0 is set; otherwise disable.
	ColorAuto ColorPreference = iota
	// ColorDisable suppresses ANSI escapes unconditionally. Wired to
	// --no-color and to NO_COLOR / CLICOLOR=0.
	ColorDisable
	// ColorEnable forces ANSI escapes on regardless of TTY. Wired to
	// CLICOLOR_FORCE.
	ColorEnable
)

// ResolveColorEnabled decides whether the report renderer should emit
// ANSI escapes. Resolution rules, in priority order:
//
//  1. Explicit --no-color (pref == ColorDisable): off.
//  2. NO_COLOR set to any non-empty value: off.
//     (https://no-color.org/ — the de-facto standard.)
//  3. CLICOLOR_FORCE set to a truthy value, or pref == ColorEnable: on.
//  4. CLICOLOR set to "0": off.
//  5. Default (pref == ColorAuto): on iff w is a *os.File pointing at
//     a TTY (best-effort; non-file writers default off).
//
// The env-var reads route through getenv so tests can pin behaviour
// without polluting the process environment. Pass os.Getenv from
// production callers.
func ResolveColorEnabled(pref ColorPreference, w io.Writer, getenv func(string) string) bool {
	if pref == ColorDisable {
		return false
	}
	if v := getenv("NO_COLOR"); v != "" {
		return false
	}
	if isTruthyEnv(getenv("CLICOLOR_FORCE")) {
		return true
	}
	if pref == ColorEnable {
		return true
	}
	if v := getenv("CLICOLOR"); v == "0" {
		return false
	}
	return isTerminalWriter(w)
}

// isTerminalWriter reports whether w is an *os.File backed by a TTY.
// Avoids pulling in golang.org/x/term — the import-graph guard in
// cli/import_graph_test.go is fine with stdlib syscall heuristics but
// the report package has no business growing a new transitive dep
// for a colour decision.
//
// The check uses os.File.Stat and tests for the character-device mode
// bit, which is what every TTY exposes on Linux/macOS and what
// Windows consoles also report through the Go runtime.
func isTerminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

// isTruthyEnv reports whether v is a "yes, this is on" env-var value.
// CLICOLOR_FORCE traditionally accepts "1" or any non-empty value;
// we accept the common spellings explicitly so a "0" or "false" is
// not treated as truthy.
func isTruthyEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "false", "no", "off":
		return false
	}
	return true
}
