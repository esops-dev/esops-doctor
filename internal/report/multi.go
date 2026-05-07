package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/findings"
)

// ClusterReport is one cluster's slice of a multi-cluster scan. Label
// is the operator-supplied identifier (URL or context name); Header
// and Results carry the same content the single-cluster path renders.
// ConnectError is non-empty when the connect step failed before the
// engine ran — every renderer surfaces it as the cluster's outcome
// instead of silently skipping the entry.
type ClusterReport struct {
	Label             string
	Header            Header
	Results           []engine.RuleResult
	ConnectError      string
	ConnectErrorClass string
}

// Errored reports whether this cluster failed before the engine ran.
// When true, Results is empty and ConnectError carries the message.
func (c ClusterReport) Errored() bool { return c.ConnectError != "" }

// RenderMulti dispatches to the per-format multi-cluster renderer.
// format is the already-validated value resolveOutput returned
// (lowercase, in the implemented set).
func RenderMulti(format string, w io.Writer, clusters []ClusterReport, opts Options) error {
	switch strings.ToLower(format) {
	case "", "table":
		return MultiTable(w, clusters, TableOptions(opts))
	case "json":
		return MultiJSON(w, clusters, opts)
	case "yaml":
		return MultiYAML(w, clusters, opts)
	case "sarif":
		return MultiSARIF(w, clusters, opts)
	case "junit":
		return MultiJUnit(w, clusters, opts)
	case "html":
		return MultiHTML(w, clusters, opts)
	default:
		return fmt.Errorf("output format %q not implemented", format)
	}
}

// MaxFailingSeverityFleet returns the most urgent severity across
// every cluster in the fleet. Used by the cli to decide the
// fleet-wide exit code: if any cluster's findings clear the
// --fail-on threshold, the whole scan exits 20.
func MaxFailingSeverityFleet(clusters []ClusterReport) findings.Severity {
	max := findings.SeverityUnknown
	for _, c := range clusters {
		if s := MaxFailingSeverity(c.Results); s > max {
			max = s
		}
	}
	return max
}

// MultiTable writes one block per cluster followed by a fleet-wide
// summary line. Each block reuses the single-cluster Table renderer so
// per-cluster formatting (including the "no findings against X" line
// and the per-cluster summary) stays identical to the single-cluster
// output an operator already knows.
//
// Connect failures render as a small error block above the per-cluster
// summary so a fleet operator sees the unreachable cluster in the
// linear scroll without having to cross-reference logs.
func MultiTable(w io.Writer, clusters []ClusterReport, opts TableOptions) error {
	for i, c := range clusters {
		if i > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if err := writeMultiTableHeader(w, c, i+1, len(clusters)); err != nil {
			return err
		}
		if c.Errored() {
			if _, err := fmt.Fprintf(w, "  connect failed (%s): %s\n",
				c.ConnectErrorClass, c.ConnectError); err != nil {
				return err
			}
			continue
		}
		if err := Table(w, c.Header, c.Results, opts); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	return writeFleetSummary(w, clusters)
}

func writeMultiTableHeader(w io.Writer, c ClusterReport, n, total int) error {
	label := c.Label
	if label == "" {
		label = c.Header.ClusterName
	}
	_, err := fmt.Fprintf(w, "=== cluster %d/%d: %s ===\n", n, total, label)
	return err
}

// writeFleetSummary aggregates the per-cluster summary counts so the
// fleet-wide totals appear at the bottom of a multi-cluster scan. An
// operator who pipes the output to a CI log gets a single grep-able
// line without losing the per-cluster detail above.
func writeFleetSummary(w io.Writer, clusters []ClusterReport) error {
	var total summary
	errored := 0
	var earliestStart time.Time
	var totalDuration time.Duration
	for _, c := range clusters {
		if !c.Header.StartedAt.IsZero() {
			if earliestStart.IsZero() || c.Header.StartedAt.Before(earliestStart) {
				earliestStart = c.Header.StartedAt
			}
		}
		totalDuration += c.Header.Duration
		if c.Errored() {
			errored++
			continue
		}
		s := classify(c.Results)
		total.critical += s.critical
		total.error += s.error
		total.warn += s.warn
		total.info += s.info
		total.passed += s.passed
		total.skipped += s.skipped
		total.errored += s.errored
		total.waived += s.waived
	}
	parts := []string{
		fmt.Sprintf("fleet: %d clusters, %d unreachable", len(clusters), errored),
		fmt.Sprintf("%d critical, %d error, %d warn, %d info; %d passed, %d skipped, %d errored, %d waived",
			total.critical, total.error, total.warn, total.info,
			total.passed, total.skipped, total.errored, total.waived),
	}
	if !earliestStart.IsZero() {
		parts = append(parts, "started "+earliestStart.UTC().Format(time.RFC3339))
	}
	if totalDuration > 0 {
		parts = append(parts, "took "+formatDuration(totalDuration))
	}
	_, err := fmt.Fprintf(w, "%s\n", strings.Join(parts, " | "))
	return err
}
