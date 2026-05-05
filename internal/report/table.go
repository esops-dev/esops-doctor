// Package report renders engine results for stdout consumption.
//
// The default table format prints one row per failing rule plus
// summary footers covering passes, skipped (with reason), and per-rule
// errors. Skipped is *reported* (not silent) per CLAUDE.md §3 so an
// operator sees that a rule was inapplicable rather than absent.
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
type TableOptions struct {
	SummaryOnly bool
	Quiet       bool
}

// Table writes the report. The header carries the cluster identity and
// scan duration so a multi-cluster log can be re-read later without
// losing context.
func Table(w io.Writer, h Header, results []engine.RuleResult, opts TableOptions) error {
	counts := classify(results)

	if !opts.SummaryOnly {
		if err := writeFindings(w, h.Dialect, results); err != nil {
			return err
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

	_, err := fmt.Fprintf(w, "summary: %d critical, %d error, %d warn, %d info; %d passed, %d skipped, %d errored | %s\n",
		counts.critical, counts.error, counts.warn, counts.info,
		counts.passed, counts.skipped, counts.errored,
		formatHeader(h),
	)
	return err
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
// and used by the cli to decide the exit code.
type summary struct {
	critical, error, warn, info int
	passed, skipped, errored    int
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

// MaxFailingSeverity returns the most urgent severity across failing
// rules, or SeverityUnknown when none failed. Used by the cli to gate
// the exit code against --fail-on without re-walking the results.
func MaxFailingSeverity(results []engine.RuleResult) findings.Severity {
	max := findings.SeverityUnknown
	for _, r := range results {
		if r.Status != engine.RuleStatusFail || r.Finding == nil {
			continue
		}
		if r.Finding.Severity > max {
			max = r.Finding.Severity
		}
	}
	return max
}

func writeFindings(w io.Writer, dialect string, results []engine.RuleResult) error {
	var fails []engine.RuleResult
	for _, r := range results {
		if r.Status == engine.RuleStatusFail {
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
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", sev, f.RuleID, f.Category, oneLine(f.Message)); err != nil {
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
