package baseline

import (
	"encoding/json"
	"fmt"

	"github.com/esops-dev/esops-doctor/internal/findings"
)

// parseJSON reads a doctor JSON Document (single-cluster or
// multi-cluster) and extracts every failing finding as a baseline
// entry. Skipped, passing and errored rows are ignored — a baseline is
// "these failures were known about" and nothing else.
//
// Multi-cluster documents carry a top-level "clusters" array; the
// loader walks both shapes so an operator can pass either as a
// baseline.
func parseJSON(data []byte, source string) (*Set, error) {
	// Probe to distinguish single-cluster from multi-cluster.
	var probe struct {
		Clusters []json.RawMessage `json:"clusters"`
		Cluster  *json.RawMessage  `json:"cluster"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parsing baseline JSON %q: %w", source, err)
	}
	if probe.Clusters != nil {
		return parseMultiJSON(data, source)
	}
	return parseSingleJSON(data, source)
}

// jsonDoc is the minimum shape needed to harvest fingerprints from a
// single-cluster doctor JSON document. The fields mirror
// report.Document but live here to keep the baseline package
// independent of report (which depends on engine, which is heavy).
type jsonDoc struct {
	SchemaVersion int          `json:"schema_version"`
	Cluster       jsonCluster  `json:"cluster"`
	Results       []jsonResult `json:"results"`
}

type jsonCluster struct {
	Dialect string `json:"dialect"`
}

type jsonResult struct {
	RuleID      string           `json:"rule_id"`
	Status      string           `json:"status"`
	Severity    string           `json:"severity"`
	Message     string           `json:"message"`
	Target      string           `json:"target"`
	Fingerprint *jsonFingerprint `json:"fingerprint"`
}

// jsonFingerprint is the dedicated finding-identity block on the
// Result row (schema_version 1). When present it wins over the
// fallback (Cluster.Dialect + RuleID + per-result Target); when
// absent the fallback path keeps working so older Document JSON
// still parses.
type jsonFingerprint struct {
	RuleID  string `json:"rule_id"`
	Dialect string `json:"dialect"`
	Target  string `json:"target"`
}

func parseSingleJSON(data []byte, source string) (*Set, error) {
	var doc jsonDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing baseline JSON %q: %w", source, err)
	}
	entries := entriesFromJSON(doc.Cluster.Dialect, doc.Results)
	return NewSet(entries, source, "json"), nil
}

// jsonMulti carries enough of report.FleetDocument to harvest the
// per-cluster fingerprints. The wire shape nests each cluster's
// results under a `document` block — matches report.FleetEntry.
// Skipped (connect-failed) clusters carry no Document and contribute
// nothing to the baseline.
type jsonMulti struct {
	Clusters []struct {
		Document *struct {
			Cluster jsonCluster  `json:"cluster"`
			Results []jsonResult `json:"results"`
		} `json:"document"`
	} `json:"clusters"`
}

func parseMultiJSON(data []byte, source string) (*Set, error) {
	var doc jsonMulti
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing baseline JSON %q: %w", source, err)
	}
	var entries []Entry
	for _, c := range doc.Clusters {
		if c.Document == nil {
			continue
		}
		entries = append(entries, entriesFromJSON(c.Document.Cluster.Dialect, c.Document.Results)...)
	}
	return NewSet(entries, source, "json"), nil
}

// entriesFromJSON turns the report's per-result rows into baseline
// entries. Only status=="fail" rows are kept — passes, skips, errors,
// and active waivers were not failures at the time the baseline was
// written, so they shouldn't suppress a fresh failure now.
func entriesFromJSON(dialect string, results []jsonResult) []Entry {
	out := make([]Entry, 0, len(results))
	for _, r := range results {
		if r.Status != "fail" {
			continue
		}
		sev, _ := findings.ParseSeverity(r.Severity)
		fp := Fingerprint{
			RuleID:  r.RuleID,
			Dialect: dialect,
			Target:  r.Target,
		}
		// Prefer the explicit fingerprint block when the producer
		// wrote one (post schema_version 1 contract). Keeps the
		// future per-target finding shape additive.
		if r.Fingerprint != nil {
			if r.Fingerprint.RuleID != "" {
				fp.RuleID = r.Fingerprint.RuleID
			}
			if r.Fingerprint.Dialect != "" {
				fp.Dialect = r.Fingerprint.Dialect
			}
			if r.Fingerprint.Target != "" {
				fp.Target = r.Fingerprint.Target
			}
		}
		out = append(out, Entry{
			Fingerprint: fp,
			Severity:    sev,
			Message:     r.Message,
		})
	}
	return out
}
