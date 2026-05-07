package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/esops-dev/esops-doctor/internal/version"
)

// MultiSARIF emits a single SARIF document containing one `runs[]`
// entry per cluster — SARIF natively models multi-target output this
// way, so GitHub code-scanning and similar consumers ingest the fleet
// scan as a coherent group rather than as N separate uploads.
//
// Connect-failed clusters become a run with no results and an
// invocations[].executionSuccessful=false marker, matching the SARIF
// recommendation for "the tool tried but couldn't analyse this
// target". The per-run driver block carries the cluster label so
// downstreams can attribute findings.
func MultiSARIF(w io.Writer, clusters []ClusterReport, opts Options) error {
	doc := sarifDoc{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs:    make([]sarifRun, 0, len(clusters)),
	}
	for _, c := range clusters {
		if c.Errored() {
			doc.Runs = append(doc.Runs, sarifRun{
				Tool: sarifTool{Driver: sarifDriver{
					Name:           "esops-doctor",
					Version:        version.Version,
					InformationURI: sarifToolURI,
					Rules:          []sarifRule{},
				}},
				Results: []sarifResult{},
				Invocs:  []sarifInvoc{{ExecutionSuccessful: false}},
			})
			continue
		}
		run := buildSarif(c.Header, c.Results, opts).Runs[0]
		doc.Runs = append(doc.Runs, run)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encoding multi-cluster sarif report: %w", err)
	}
	return nil
}
