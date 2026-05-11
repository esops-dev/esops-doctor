package baseline

import (
	"encoding/json"
	"fmt"

	"github.com/esops-dev/esops-doctor/internal/findings"
)

// parseSARIF harvests one Entry per failing SARIF result. The
// fingerprint is read from result.partialFingerprints (the canonical
// place when doctor wrote the file) and falls back to (ruleId,
// dialect-from-driver-properties) for legacy SARIF written before the
// partialFingerprints scheme landed.
//
// Doctor's SARIF emitter today writes one run per cluster, with the
// run-level driver.properties.dialect set so a multi-cluster SARIF
// round-trips. Other producers' SARIF that doesn't carry a dialect
// falls back to "" for that field; the match key then collapses to
// (rule_id, "") and matches whatever current finding shares the rule
// id. That's the desired behaviour: a baseline written from a sister
// tool should still suppress matching rule_ids; explicit dialect
// scoping only kicks in when the baseline carries it.
func parseSARIF(data []byte, source string) (*Set, error) {
	var doc sarifFile
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing baseline SARIF %q: %w", source, err)
	}
	var entries []Entry
	for _, run := range doc.Runs {
		dialect := run.dialect()
		for _, r := range run.Results {
			if r.Kind != "" && r.Kind != "fail" {
				// Skipped, passing and errored rows do not belong in
				// the baseline.
				continue
			}
			if r.Kind == "" && r.Level == "" {
				// Some SARIF producers emit a result without kind or
				// level for non-failures. Be conservative: only treat
				// rows that look like failures (kind=="fail" or a
				// non-empty failure level) as baseline-worthy.
				continue
			}
			fp := r.fingerprint(dialect)
			if fp.RuleID == "" {
				continue
			}
			entries = append(entries, Entry{
				Fingerprint: fp,
				Severity:    severityFromSARIF(r.Level),
				Message:     r.message(),
			})
		}
	}
	return NewSet(entries, source, "sarif"), nil
}

// sarifFile is the trimmed subset of the SARIF 2.1.0 shape this
// loader cares about. Anything else in the file (rule-list metadata,
// extensions) is intentionally ignored — the baseline match key is
// the fingerprint alone.
type sarifFile struct {
	Runs []sarifFileRun `json:"runs"`
}

type sarifFileRun struct {
	Tool    sarifFileTool     `json:"tool"`
	Results []sarifFileResult `json:"results"`
}

type sarifFileTool struct {
	Driver sarifFileDriver `json:"driver"`
}

type sarifFileDriver struct {
	Name       string                 `json:"name"`
	Properties map[string]interface{} `json:"properties"`
}

// dialect returns the run's dialect, read from
// tool.driver.properties.dialect. Empty when the producer did not
// embed one.
func (r sarifFileRun) dialect() string {
	v, _ := r.Tool.Driver.Properties["dialect"].(string)
	return v
}

type sarifFileResult struct {
	RuleID              string            `json:"ruleId"`
	Kind                string            `json:"kind"`
	Level               string            `json:"level"`
	Message             sarifFileMessage  `json:"message"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifFileMessage struct {
	Text string `json:"text"`
}

func (r sarifFileResult) message() string { return r.Message.Text }

// fingerprint pulls the canonical (rule_id, dialect, target) from a
// SARIF result. Preference order:
//   - partialFingerprints carries the doctor-written canonical keys.
//   - Fall back to ruleId and the run-level dialect.
//
// The target slot stays empty unless partialFingerprints declares it,
// which is the schema 1 contract: targets are opt-in per result.
func (r sarifFileResult) fingerprint(runDialect string) Fingerprint {
	fp := Fingerprint{
		RuleID:  r.RuleID,
		Dialect: runDialect,
	}
	if id, ok := r.PartialFingerprints["rule_id"]; ok && id != "" {
		fp.RuleID = id
	}
	if d, ok := r.PartialFingerprints["dialect"]; ok && d != "" {
		fp.Dialect = d
	}
	if t, ok := r.PartialFingerprints["target"]; ok && t != "" {
		fp.Target = t
	}
	return fp
}

// severityFromSARIF maps the four-level SARIF range back to a doctor
// Severity. SARIF collapses critical → error on emit, so the round
// trip is lossy: a critical finding round-trips as SeverityError.
// Diff's severity-changed reporting is aware of the collapse and only
// flags changes that cross a SARIF-level boundary.
func severityFromSARIF(level string) findings.Severity {
	switch level {
	case "note":
		return findings.SeverityInfo
	case "warning":
		return findings.SeverityWarn
	case "error":
		return findings.SeverityError
	default:
		return findings.SeverityUnknown
	}
}
