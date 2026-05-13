// Package report renders engine results for stdout consumption.
//
// The default table format prints one row per failing rule plus
// summary footers covering passes, skipped (with reason), and per-rule
// errors. Skipped is *reported* (not silent) so an operator sees
// that a rule was inapplicable rather than absent.
package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/findings"
)

// Header carries the per-scan context the report renders alongside
// the rule rows: the cluster the scan ran against, plus the wall-clock
// time the engine took. The fields are filled by the cli before the
// table is emitted so a captured log line on a busy oncall channel
// stays interpretable on its own.
//
// The Tool* and cluster-health fields are read by the json/yaml/sarif/
// junit/html renderers via Document; the table renderer only needs
// ClusterName/Dialect/Version/Duration. Filling the extra fields is
// optional — empty values are omitted from structured output, and the
// table renderer ignores them.
type Header struct {
	ClusterName string
	Dialect     string
	Version     string

	Health        string
	NodeCount     int
	DataNodeCount int

	StartedAt time.Time
	Duration  time.Duration

	ToolName        string
	ToolVersion     string
	ToolCommit      string
	ToolEsopsModule string
}

// TableOptions tunes the renderer's verbosity.
//
//   - SummaryOnly: print only the one-line counts footer; suppress the
//     per-finding rows and the per-skipped/per-error sections. Wired to
//     the --summary-only flag.
//   - Quiet: drop the per-skipped section and the empty "0 findings"
//     row. The findings table itself still prints when there are any,
//     since operator-facing severity events are not "noise". Wired to
//     --quiet (which also lowers the slog level — that part lives in
//     the logging init, not here).
//   - IncludePassed: emit a "passed (N)" section listing the rules
//     that ran cleanly. Off by default — operators who want a human
//     "what was checked" report flip it on with --include-passed.
//   - Color: tint severity tokens with ANSI escapes. Resolved at the
//     cli boundary against --no-color and NO_COLOR / CLICOLOR /
//     CLICOLOR_FORCE so the report package never reads the env itself.
type TableOptions struct {
	SummaryOnly   bool
	Quiet         bool
	IncludePassed bool
	Color         bool
}

// Table writes the report. The header carries the cluster identity and
// scan duration so a multi-cluster log can be re-read later without
// losing context.
func Table(w io.Writer, h Header, results []engine.RuleResult, opts TableOptions) error {
	counts := classify(results)

	if !opts.SummaryOnly {
		if err := writeFindings(w, h.Dialect, results, opts.Color); err != nil {
			return err
		}
		if err := writeEsopsHints(w, results); err != nil {
			return err
		}
		if err := writeWaived(w, results); err != nil {
			return err
		}
		if err := writeBaselined(w, results, opts.Color); err != nil {
			return err
		}
		if opts.IncludePassed {
			if err := writePassed(w, results); err != nil {
				return err
			}
		}
		if !opts.Quiet {
			if err := writeSkipped(w, results); err != nil {
				return err
			}
		}
		if err := writeErrors(w, results); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintf(w, "summary: %d critical, %d error, %d warn, %d info; %d passed, %d skipped, %d errored, %d waived, %d baselined | %s\n",
		counts.critical, counts.error, counts.warn, counts.info,
		counts.passed, counts.skipped, counts.errored, counts.waived, counts.baselined,
		formatHeader(h),
	)
	return err
}

// writeBaselined emits the baseline-matched section. Failures that
// match an operator-supplied baseline render here so a brownfield CI
// gate sees both "these were known" and "these are new" in the same
// report.
func writeBaselined(w io.Writer, results []engine.RuleResult, color bool) error {
	var rows []engine.RuleResult
	for _, r := range results {
		if r.Status == engine.RuleStatusFail && isBaselined(r.Finding) && !isActiveWaiver(r.Finding) {
			rows = append(rows, r)
		}
	}
	if len(rows) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "\nbaselined (%d):\n", len(rows)); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, r := range rows {
		f := r.Finding
		sev := f.Severity.String()
		if sev == "" {
			sev = "?"
		}
		src := ""
		if f.Baseline != nil {
			src = f.Baseline.Source
		}
		if _, err := fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n",
			colorize(sev, f.Severity, color), f.RuleID, src, oneLine(f.Message)); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// writePassed emits the per-passed-rule section. Off by default; the
// scan command's --include-passed flag flips it on so an operator can
// see a "what was checked" report alongside the failure rows. The
// summary footer always carries the passed count regardless.
func writePassed(w io.Writer, results []engine.RuleResult) error {
	var rows []engine.RuleResult
	for _, r := range results {
		if r.Status == engine.RuleStatusPass {
			rows = append(rows, r)
		}
	}
	if len(rows) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "\npassed (%d):\n", len(rows)); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, r := range rows {
		category := r.Rule.Category
		name := r.Rule.Name
		if _, err := fmt.Fprintf(tw, "  %s\t%s\t%s\n",
			r.RuleID, category, oneLine(name)); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// formatHeader renders the cluster identity line that follows the
// counts. Empty fields are silently elided so the renderer works the
// same whether the caller filled in everything (cli.scan) or just a
// dialect (legacy tests).
func formatHeader(h Header) string {
	parts := make([]string, 0, 4)
	switch {
	case h.ClusterName != "" && h.Version != "":
		parts = append(parts, fmt.Sprintf("cluster=%q (%s %s)", h.ClusterName, h.Dialect, h.Version))
	case h.ClusterName != "":
		parts = append(parts, fmt.Sprintf("cluster=%q (%s)", h.ClusterName, h.Dialect))
	case h.Dialect != "":
		parts = append(parts, fmt.Sprintf("dialect=%s", h.Dialect))
	}
	if h.Duration > 0 {
		parts = append(parts, "took "+formatDuration(h.Duration))
	}
	return strings.Join(parts, ", ")
}

// formatDuration renders a duration with a sensible unit. time.Duration's
// own Stringer prints "8.234567ms"; trimming to two fractional digits
// keeps the summary line readable.
func formatDuration(d time.Duration) string {
	switch {
	case d >= time.Second:
		return fmt.Sprintf("%.2fs", d.Seconds())
	case d >= time.Millisecond:
		return fmt.Sprintf("%dms", d.Milliseconds())
	default:
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
}

// summary is the per-status / per-severity tally surfaced in the footer
// and used by the cli to decide the exit code. Waived counts active
// (non-expired) waivers; expired waivers fall back into the severity
// columns because the suppression failed and the finding fires loud.
// Baselined counts findings matched against an operator-supplied
// baseline (--baseline); those are excluded from the severity columns
// just like active waivers — a baseline-matched failure does not
// trip the --fail-on gate.
type summary struct {
	critical, error, warn, info int
	passed, skipped, errored    int
	waived                      int
	baselined                   int
}

func classify(results []engine.RuleResult) summary {
	var s summary
	for _, r := range results {
		switch r.Status {
		case engine.RuleStatusPass:
			s.passed++
		case engine.RuleStatusSkipped:
			s.skipped++
		case engine.RuleStatusError:
			s.errored++
		case engine.RuleStatusFail:
			if r.Finding == nil {
				continue
			}
			if isActiveWaiver(r.Finding) {
				s.waived++
				continue
			}
			if isBaselined(r.Finding) {
				s.baselined++
				continue
			}
			switch r.Finding.Severity {
			case findings.SeverityCritical:
				s.critical++
			case findings.SeverityError:
				s.error++
			case findings.SeverityWarn:
				s.warn++
			case findings.SeverityInfo:
				s.info++
			}
		}
	}
	return s
}

// isActiveWaiver reports whether f carries a non-expired suppression.
// Pulled out so the report and exit-code paths agree on a single
// definition — drift between the two would let a build pass despite a
// failure showing in the report (or vice versa).
func isActiveWaiver(f *findings.Finding) bool {
	return f != nil && f.Suppression != nil && !f.Suppression.Expired
}

// isBaselined reports whether f matched an operator-supplied baseline
// entry. Baselined findings are excluded from the fail-on gate so an
// operator adopting doctor on a brownfield cluster can wire the gate
// today without "fix everything in one go".
func isBaselined(f *findings.Finding) bool {
	return f != nil && f.Baseline != nil
}

// MaxFailingSeverity returns the most urgent severity across failing
// rules, or SeverityUnknown when none failed. Findings with an active
// (non-expired) waiver, or a baseline match, are excluded so the
// operator's documented exception clears the --fail-on gate.
func MaxFailingSeverity(results []engine.RuleResult) findings.Severity {
	max := findings.SeverityUnknown
	for _, r := range results {
		if r.Status != engine.RuleStatusFail || r.Finding == nil {
			continue
		}
		if isActiveWaiver(r.Finding) {
			continue
		}
		if isBaselined(r.Finding) {
			continue
		}
		if r.Finding.Severity > max {
			max = r.Finding.Severity
		}
	}
	return max
}

// writeFindings emits the live-failure table: anything that fails and
// either has no waiver or has one that's already expired. An expired
// waiver lands in this table (its message already carries the
// "[waiver expired …]" prefix from the waivers Apply step) so the
// failure stays loud. Baseline-matched findings are excluded — they
// render in their own section so a brownfield-baseline report stays
// readable.
func writeFindings(w io.Writer, dialect string, results []engine.RuleResult, color bool) error {
	var fails []engine.RuleResult
	for _, r := range results {
		if r.Status == engine.RuleStatusFail && !isActiveWaiver(r.Finding) && !isBaselined(r.Finding) {
			fails = append(fails, r)
		}
	}
	if len(fails) == 0 {
		_, err := fmt.Fprintf(w, "no findings against %s\n", dialect)
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "SEVERITY\tRULE\tCATEGORY\tMESSAGE"); err != nil {
		return err
	}
	for _, r := range fails {
		f := r.Finding
		sev := f.Severity.String()
		if sev == "" {
			sev = "?"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", colorize(sev, f.Severity, color), f.RuleID, f.Category, oneLine(f.Message)); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// writeEsopsHints emits a per-finding list of suggested `esops`
// subcommands for failures that carry them in their remediation. Active
// waivers are excluded so a documented exception doesn't generate
// remediation noise; expired waivers stay in because the failure is
// live again.
func writeEsopsHints(w io.Writer, results []engine.RuleResult) error {
	type hint struct {
		ruleID   string
		commands []string
	}
	var hints []hint
	for _, r := range results {
		if r.Status != engine.RuleStatusFail || r.Finding == nil {
			continue
		}
		if isActiveWaiver(r.Finding) {
			continue
		}
		if cmds := r.Finding.Remediation.EsopsCommands; len(cmds) > 0 {
			hints = append(hints, hint{ruleID: r.Finding.RuleID, commands: cmds})
		}
	}
	if len(hints) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "\nesops remediation (%d):\n", len(hints)); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, h := range hints {
		if _, err := fmt.Fprintf(tw, "  %s\t%s\n", h.ruleID, strings.Join(h.commands, "; ")); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// writeWaived emits the active-waiver section. Listed separately from
// the live-failure table so an operator scanning the report can see
// "what would have failed but is documented as accepted" — and so that
// expanding the waivers file or letting one expire doesn't change
// where the row lives.
func writeWaived(w io.Writer, results []engine.RuleResult) error {
	var waived []engine.RuleResult
	for _, r := range results {
		if r.Status == engine.RuleStatusFail && isActiveWaiver(r.Finding) {
			waived = append(waived, r)
		}
	}
	if len(waived) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "\nwaived (%d):\n", len(waived)); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, r := range waived {
		f := r.Finding
		sup := f.Suppression
		exp := "no expiry"
		if sup.ExpiresAt != nil {
			exp = "expires " + sup.ExpiresAt.UTC().Format("2006-01-02")
		}
		if _, err := fmt.Fprintf(tw, "  %s\t%s\t%s\n",
			r.RuleID, exp, oneLine(sup.Justification)); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func writeSkipped(w io.Writer, results []engine.RuleResult) error {
	var skips []engine.RuleResult
	for _, r := range results {
		if r.Status == engine.RuleStatusSkipped {
			skips = append(skips, r)
		}
	}
	if len(skips) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "\nskipped (%d):\n", len(skips)); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, r := range skips {
		if _, err := fmt.Fprintf(tw, "  %s\t%s\n", r.RuleID, r.SkipReason); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func writeErrors(w io.Writer, results []engine.RuleResult) error {
	var errs []engine.RuleResult
	for _, r := range results {
		if r.Status == engine.RuleStatusError {
			errs = append(errs, r)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "\nerrors (%d):\n", len(errs)); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, r := range errs {
		msg := "unknown"
		if r.Err != nil {
			msg = r.Err.Error()
		}
		if _, err := fmt.Fprintf(tw, "  %s\t%s\n", r.RuleID, oneLine(msg)); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// oneLine collapses a multi-line message to a single line so the table
// stays aligned. Newlines become " | "; tabs become spaces because
// tabwriter would mis-align on embedded tabs.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " | ")
	s = strings.ReplaceAll(s, "\t", " ")
	return s
}
