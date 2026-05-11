package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/urfave/cli/v3"

	"github.com/esops-dev/esops-doctor/internal/baseline"
	"github.com/esops-dev/esops-doctor/internal/exit"
)

// diffCommand compares two scan reports and prints added / resolved /
// severity-changed findings. Both inputs can be SARIF or doctor JSON
// — the loader auto-detects the format. The output is operator-
// readable by default; --output json emits a stable wire shape for
// CI integrations that want to gate on regressions.
//
// Exit code 20 fires when the new report introduced any finding the
// old report did not carry. Severity-changed (regressed) findings
// also count toward exit 20 when the new severity is higher than the
// old. Resolutions never trip the gate.
func diffCommand() *cli.Command {
	return &cli.Command{
		Name:      "diff",
		Usage:     "Compare two scan reports and print added / resolved / severity-changed findings",
		ArgsUsage: "OLD NEW",
		Description: "OLD and NEW are previous-scan reports in SARIF or doctor JSON.\n" +
			"Added findings exit 20 (regression); resolved findings never fail\n" +
			"the gate. Use diff for ratchet visibility per scan.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:      "output",
				Aliases:   []string{"o"},
				Value:     "table",
				Usage:     "Output format: table | json",
				Validator: validateDiffOutput,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runDiff(ctx, cmd, cmdWriter(cmd))
		},
	}
}

func validateDiffOutput(s string) error {
	switch strings.ToLower(s) {
	case "", "table", "json":
		return nil
	}
	return exit.Usage("--output %q is not supported for diff (accepted: table, json)", s)
}

func runDiff(_ context.Context, cmd *cli.Command, stdout io.Writer) error {
	args := cmd.Args().Slice()
	if len(args) != 2 {
		return exit.Usage("diff takes exactly two positional arguments: OLD NEW")
	}
	oldPath, newPath := args[0], args[1]
	for _, p := range []string{oldPath, newPath} {
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				return exit.Usage("%s", err.Error())
			}
			return exit.Catalog("%s", err.Error())
		}
	}

	oldSet, err := baseline.Load(oldPath)
	if err != nil {
		return exit.Catalog("loading OLD: %s", err.Error())
	}
	newSet, err := baseline.Load(newPath)
	if err != nil {
		return exit.Catalog("loading NEW: %s", err.Error())
	}

	d := baseline.Compare(oldSet, newSet)

	format := strings.ToLower(cmd.String("output"))
	if format == "" {
		format = "table"
	}
	switch format {
	case "json":
		if err := renderDiffJSON(stdout, oldPath, newPath, d); err != nil {
			return fmt.Errorf("rendering diff json: %w", err)
		}
	default:
		if err := renderDiffTable(stdout, oldPath, newPath, d); err != nil {
			return fmt.Errorf("rendering diff table: %w", err)
		}
	}

	if regressed(d) {
		return exit.Silent(fmt.Errorf("%w: %d added, %d severity-regressed",
			exit.ErrFindings, len(d.Added), countRegressed(d.SeverityChanged)))
	}
	return nil
}

// regressed reports whether the new scan introduced any finding the
// old scan did not carry, or raised the severity of an existing one.
// Resolutions and severity drops never count as regressions.
func regressed(d baseline.Diff) bool {
	if len(d.Added) > 0 {
		return true
	}
	return countRegressed(d.SeverityChanged) > 0
}

// countRegressed counts severity-changes where the new severity is
// strictly higher than the old. Drops don't count.
func countRegressed(cs []baseline.SeverityChange) int {
	n := 0
	for _, c := range cs {
		if c.New.Severity > c.Old.Severity {
			n++
		}
	}
	return n
}

func renderDiffTable(w io.Writer, oldPath, newPath string, d baseline.Diff) error {
	if _, err := fmt.Fprintf(w, "diff: %s → %s\n", oldPath, newPath); err != nil {
		return err
	}
	if d.Empty() {
		_, err := fmt.Fprintln(w, "no changes")
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if len(d.Added) > 0 {
		if _, err := fmt.Fprintf(w, "\nadded (%d):\n", len(d.Added)); err != nil {
			return err
		}
		for _, e := range d.Added {
			if _, err := fmt.Fprintf(tw, "  + %s\t%s\t%s\n",
				severityOr(e.Severity.String()),
				e.Fingerprint, oneLineDiff(e.Message)); err != nil {
				return err
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if len(d.Resolved) > 0 {
		if _, err := fmt.Fprintf(w, "\nresolved (%d):\n", len(d.Resolved)); err != nil {
			return err
		}
		for _, e := range d.Resolved {
			if _, err := fmt.Fprintf(tw, "  - %s\t%s\t%s\n",
				severityOr(e.Severity.String()),
				e.Fingerprint, oneLineDiff(e.Message)); err != nil {
				return err
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if len(d.SeverityChanged) > 0 {
		if _, err := fmt.Fprintf(w, "\nseverity-changed (%d):\n", len(d.SeverityChanged)); err != nil {
			return err
		}
		for _, c := range d.SeverityChanged {
			direction := "→"
			if c.New.Severity > c.Old.Severity {
				direction = "↑"
			} else if c.New.Severity < c.Old.Severity {
				direction = "↓"
			}
			if _, err := fmt.Fprintf(tw, "  %s %s %s %s\t%s\n",
				direction,
				severityOr(c.Old.Severity.String()),
				direction,
				severityOr(c.New.Severity.String()),
				c.New.Fingerprint); err != nil {
				return err
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "\nsummary: %d added, %d resolved, %d severity-changed (%d regressed)\n",
		len(d.Added), len(d.Resolved), len(d.SeverityChanged), countRegressed(d.SeverityChanged))
	return err
}

// diffJSONDoc is the wire shape of `diff --output json`. Schema is
// owned by SchemaVersion (pinned at 1); additive fields don't bump.
type diffJSONDoc struct {
	SchemaVersion int                 `json:"schema_version"`
	Old           string              `json:"old"`
	New           string              `json:"new"`
	Summary       diffJSONSummary     `json:"summary"`
	Added         []diffJSONEntry     `json:"added,omitempty"`
	Resolved      []diffJSONEntry     `json:"resolved,omitempty"`
	Severity      []diffJSONSevChange `json:"severity_changed,omitempty"`
}

type diffJSONSummary struct {
	Added           int `json:"added"`
	Resolved        int `json:"resolved"`
	SeverityChanged int `json:"severity_changed"`
	Regressed       int `json:"regressed"`
}

type diffJSONEntry struct {
	RuleID   string `json:"rule_id"`
	Dialect  string `json:"dialect"`
	Target   string `json:"target,omitempty"`
	Severity string `json:"severity,omitempty"`
	Message  string `json:"message,omitempty"`
}

type diffJSONSevChange struct {
	RuleID      string `json:"rule_id"`
	Dialect     string `json:"dialect"`
	Target      string `json:"target,omitempty"`
	OldSeverity string `json:"old_severity"`
	NewSeverity string `json:"new_severity"`
}

func renderDiffJSON(w io.Writer, oldPath, newPath string, d baseline.Diff) error {
	doc := diffJSONDoc{
		SchemaVersion: 1,
		Old:           oldPath,
		New:           newPath,
		Summary: diffJSONSummary{
			Added:           len(d.Added),
			Resolved:        len(d.Resolved),
			SeverityChanged: len(d.SeverityChanged),
			Regressed:       countRegressed(d.SeverityChanged),
		},
	}
	for _, e := range d.Added {
		doc.Added = append(doc.Added, entryToJSON(e))
	}
	for _, e := range d.Resolved {
		doc.Resolved = append(doc.Resolved, entryToJSON(e))
	}
	for _, c := range d.SeverityChanged {
		doc.Severity = append(doc.Severity, diffJSONSevChange{
			RuleID:      c.New.Fingerprint.RuleID,
			Dialect:     c.New.Fingerprint.Dialect,
			Target:      c.New.Fingerprint.Target,
			OldSeverity: c.Old.Severity.String(),
			NewSeverity: c.New.Severity.String(),
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

func entryToJSON(e baseline.Entry) diffJSONEntry {
	return diffJSONEntry{
		RuleID:   e.Fingerprint.RuleID,
		Dialect:  e.Fingerprint.Dialect,
		Target:   e.Fingerprint.Target,
		Severity: e.Severity.String(),
		Message:  e.Message,
	}
}

// oneLineDiff is the diff-side mirror of report.oneLine: collapse
// embedded newlines and tabs so a multi-line message doesn't break
// table alignment. Pulled local rather than imported from report to
// keep cli/diff.go free of a renderer dependency.
func oneLineDiff(s string) string {
	s = strings.ReplaceAll(s, "\n", " | ")
	s = strings.ReplaceAll(s, "\t", " ")
	return s
}

// severityOr returns s or "?" when empty so the table doesn't
// print a hanging blank for SeverityUnknown rows (e.g. a baseline
// entry written by a producer that didn't record severity).
func severityOr(s string) string {
	if s == "" {
		return "?"
	}
	return s
}
