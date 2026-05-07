package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	yaml "go.yaml.in/yaml/v3"

	"github.com/esops-dev/esops-doctor/internal/version"
)

// FleetDocument is the JSON/YAML wire shape of a multi-cluster scan.
// Wraps a list of per-cluster Document values plus a fleet-wide tool
// block and rolled-up summary so a downstream consumer can read the
// "any cluster failed?" question off one place.
//
// Tool is duplicated from the per-cluster Document.Tool because the
// fleet-level tool block is what an aggregator pins schema_version
// against; per-cluster Tool stays stable for downstreams that
// post-process individual clusters.
type FleetDocument struct {
	SchemaVersion int          `json:"schema_version" yaml:"schema_version"`
	Tool          Tool         `json:"tool" yaml:"tool"`
	Scan          FleetScan    `json:"scan" yaml:"scan"`
	Fleet         FleetSummary `json:"fleet" yaml:"fleet"`
	Clusters      []FleetEntry `json:"clusters" yaml:"clusters"`
}

// FleetScan carries the wall-clock metadata for the entire fleet run.
// StartedAt is the earliest per-cluster start (RFC3339 UTC) so a
// downstream tailing reports has a stable chronological key; DurationMs
// is the sum of per-cluster wall-clock durations because the scan
// walks targets sequentially. Both fields elide cleanly when no
// cluster filled in a Header (legacy callers building FleetDocument by
// hand) so absent metadata renders empty rather than 1970-01-01.
type FleetScan struct {
	StartedAt  string `json:"started_at,omitempty" yaml:"started_at,omitempty"`
	DurationMs int64  `json:"duration_ms" yaml:"duration_ms"`
}

// FleetEntry is one cluster's slot in the fleet document. When the
// cluster's connect failed, Document is omitted and ConnectError /
// ConnectErrorClass capture the per-cluster failure so a downstream
// distinguishes "scanned and clean" from "could not scan at all".
type FleetEntry struct {
	Label             string    `json:"label,omitempty" yaml:"label,omitempty"`
	ConnectError      string    `json:"connect_error,omitempty" yaml:"connect_error,omitempty"`
	ConnectErrorClass string    `json:"connect_error_class,omitempty" yaml:"connect_error_class,omitempty"`
	Document          *Document `json:"document,omitempty" yaml:"document,omitempty"`
}

// FleetSummary rolls every cluster's Summary into one block plus a
// per-cluster count breakdown. Connect failures sit in
// ClustersUnreachable so a downstream that wants "did the gate pass"
// can pair the fleet finding totals with the unreachable count.
type FleetSummary struct {
	ClustersTotal       int            `json:"clusters_total" yaml:"clusters_total"`
	ClustersScanned     int            `json:"clusters_scanned" yaml:"clusters_scanned"`
	ClustersUnreachable int            `json:"clusters_unreachable" yaml:"clusters_unreachable"`
	Passed              int            `json:"passed" yaml:"passed"`
	Failed              int            `json:"failed" yaml:"failed"`
	Skipped             int            `json:"skipped" yaml:"skipped"`
	Errored             int            `json:"errored" yaml:"errored"`
	Waived              int            `json:"waived" yaml:"waived"`
	BySeverity          SeverityCounts `json:"by_severity" yaml:"by_severity"`
}

// MultiJSON writes a FleetDocument as pretty-printed JSON.
func MultiJSON(w io.Writer, clusters []ClusterReport, opts Options) error {
	doc := buildFleetDocument(clusters, opts)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encoding multi-cluster json report: %w", err)
	}
	return nil
}

// MultiYAML writes a FleetDocument as YAML, mirroring MultiJSON.
func MultiYAML(w io.Writer, clusters []ClusterReport, opts Options) error {
	doc := buildFleetDocument(clusters, opts)
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encoding multi-cluster yaml report: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("closing yaml encoder: %w", err)
	}
	return nil
}

// buildFleetDocument constructs the wire shape from per-cluster reports.
// Errored clusters carry only the connect-error fields; reachable ones
// embed the same Document a single-cluster scan would emit, so a
// downstream can pluck per-cluster results without learning a second
// schema.
func buildFleetDocument(clusters []ClusterReport, opts Options) FleetDocument {
	doc := FleetDocument{
		SchemaVersion: SchemaVersion,
		Tool: Tool{
			Name:        "esops-doctor",
			Version:     version.Version,
			Commit:      version.Commit,
			EsopsModule: version.EsopsModule,
		},
		Fleet:    FleetSummary{ClustersTotal: len(clusters)},
		Clusters: make([]FleetEntry, 0, len(clusters)),
	}
	var earliestStart time.Time
	var totalDuration time.Duration
	for _, c := range clusters {
		entry := FleetEntry{Label: c.Label}
		if !c.Header.StartedAt.IsZero() {
			if earliestStart.IsZero() || c.Header.StartedAt.Before(earliestStart) {
				earliestStart = c.Header.StartedAt
			}
		}
		totalDuration += c.Header.Duration
		if c.Errored() {
			entry.ConnectError = c.ConnectError
			entry.ConnectErrorClass = c.ConnectErrorClass
			doc.Fleet.ClustersUnreachable++
			doc.Clusters = append(doc.Clusters, entry)
			continue
		}
		d := BuildDocument(c.Header, c.Results, opts)
		entry.Document = &d
		doc.Fleet.ClustersScanned++
		doc.Fleet.Passed += d.Summary.Passed
		doc.Fleet.Failed += d.Summary.Failed
		doc.Fleet.Skipped += d.Summary.Skipped
		doc.Fleet.Errored += d.Summary.Errored
		doc.Fleet.Waived += d.Summary.Waived
		doc.Fleet.BySeverity.Critical += d.Summary.BySeverity.Critical
		doc.Fleet.BySeverity.Error += d.Summary.BySeverity.Error
		doc.Fleet.BySeverity.Warn += d.Summary.BySeverity.Warn
		doc.Fleet.BySeverity.Info += d.Summary.BySeverity.Info
		doc.Clusters = append(doc.Clusters, entry)
	}
	doc.Scan = FleetScan{
		StartedAt:  formatStartedAt(earliestStart),
		DurationMs: totalDuration.Milliseconds(),
	}
	return doc
}
