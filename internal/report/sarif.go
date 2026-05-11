package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/findings"
	"github.com/esops-dev/esops-doctor/internal/version"
)

// SARIF writes the report as SARIF v2.1.0 JSON. The shape is the
// minimum that GitHub code-scanning and GitLab security dashboards
// accept — driver identity, a rules list, and results with `level`
// (severity) and `kind` (status). HTML escaping is off so URLs in
// helpUri round-trip cleanly.
//
// Status mapping (esops-doctor → SARIF kind):
//
//	fail    → fail
//	skipped → notApplicable
//	error   → review (engine eval failure; needs human attention)
//	pass    → pass
//
// Severity mapping (esops-doctor → SARIF level):
//
//	info     → note
//	warn     → warning
//	error    → error
//	critical → error  (SARIF caps at 4 levels)
//
// Honours opts.SummaryOnly (drops the results array) and opts.Quiet
// (drops pass + skipped rows). The tool driver and rule list are
// always emitted so a downstream that pins the schema sees stable
// metadata.
func SARIF(w io.Writer, h Header, results []engine.RuleResult, opts Options) error {
	doc := buildSarif(h, results, opts)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encoding sarif report: %w", err)
	}
	return nil
}

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json"
	sarifToolURI = "https://github.com/esops-dev/esops-doctor"
)

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
	Invocs  []sarifInvoc  `json:"invocations,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string         `json:"name"`
	Version        string         `json:"version"`
	InformationURI string         `json:"informationUri"`
	Rules          []sarifRule    `json:"rules"`
	Properties     map[string]any `json:"properties,omitempty"`
}

type sarifRule struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name,omitempty"`
	ShortDescription     *sarifText         `json:"shortDescription,omitempty"`
	FullDescription      *sarifText         `json:"fullDescription,omitempty"`
	Help                 *sarifText         `json:"help,omitempty"`
	HelpURI              string             `json:"helpUri,omitempty"`
	DefaultConfiguration *sarifRuleDefaults `json:"defaultConfiguration,omitempty"`
}

type sarifRuleDefaults struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	RuleIndex           int                `json:"ruleIndex"`
	Level               string             `json:"level,omitempty"`
	Kind                string             `json:"kind,omitempty"`
	Message             sarifText          `json:"message"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
	PartialFingerprints map[string]string  `json:"partialFingerprints,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

// sarifSuppression maps an active doctor waiver onto SARIF's native
// suppression model so GitHub code-scanning and similar consumers
// surface the result as accepted-with-justification rather than
// double-counting it as a fresh failure. Expired waivers do NOT
// emit a suppression — the failure is live by then, and the rotted
// waiver is already prefixed into the message text.
type sarifSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status,omitempty"`
	Justification string `json:"justification,omitempty"`
}

// sarifInvoc carries the per-run invocation block. SARIF lets a
// consumer trace when the tool ran via startTimeUtc / endTimeUtc — both
// optional, both RFC3339 with the canonical "Z" suffix. Filling them
// in lets a triage flow correlate a finding back to the scan window;
// omitting them when the caller didn't supply timing keeps the output
// well-formed for the legacy hand-built test fixtures.
type sarifInvoc struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	StartTimeUtc        string `json:"startTimeUtc,omitempty"`
	EndTimeUtc          string `json:"endTimeUtc,omitempty"`
}

func buildSarif(h Header, results []engine.RuleResult, opts Options) sarifDoc {
	rules, ruleIndex := sarifRules(results)
	driver := sarifDriver{
		Name:           "esops-doctor",
		Version:        version.Version,
		InformationURI: sarifToolURI,
		Rules:          rules,
	}
	// Embed the run's dialect on the driver.properties bag so a SARIF
	// consumer that needs to attribute findings to elasticsearch /
	// opensearch (and the baseline loader specifically) round-trips
	// it. Driver.properties is the SARIF-blessed spot for tool-
	// specific extensions; omit when empty so the legacy hand-built
	// test fixtures keep their byte-for-byte shape.
	if h.Dialect != "" {
		driver.Properties = map[string]any{"dialect": h.Dialect}
	}
	doc := sarifDoc{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: driver},
			Results: []sarifResult{},
			Invocs:  []sarifInvoc{sarifInvocFromHeader(h, !anyErrored(results))},
		}},
	}
	if opts.SummaryOnly {
		return doc
	}
	doc.Runs[0].Results = sarifResults(results, ruleIndex, opts, h.Dialect)
	return doc
}

// sarifRules walks results once and emits a stable, deduplicated rule
// list. The returned ruleIndex maps RuleID → position in rules so
// each result entry can fill in ruleIndex without a second walk.
//
// Rule metadata is sourced from r.Rule (populated for every status by
// the engine), so passing, skipped and errored rules carry the same
// name/description/helpUri/defaultLevel as failing ones. SARIF UIs
// that browse the rule catalog (e.g. GitHub's "Rules" tab) become
// genuinely useful regardless of whether the scan flagged anything.
func sarifRules(results []engine.RuleResult) ([]sarifRule, map[string]int) {
	rules := []sarifRule{}
	idx := map[string]int{}
	for _, r := range results {
		if _, seen := idx[r.RuleID]; seen {
			continue
		}
		rule := sarifRule{ID: r.RuleID}
		if r.Rule.Name != "" {
			rule.Name = r.Rule.Name
			// Mirror Name into shortDescription so SARIF UIs that
			// render the latter (some validators require it for
			// strict-mode compliance) have something to show.
			rule.ShortDescription = &sarifText{Text: r.Rule.Name}
		}
		if desc := strings.TrimSpace(r.Rule.Description); desc != "" {
			rule.FullDescription = &sarifText{Text: desc}
		}
		if r.Rule.Remediation.DocURL != "" {
			rule.HelpURI = r.Rule.Remediation.DocURL
		}
		if cmds := r.Rule.Remediation.EsopsCommands; len(cmds) > 0 {
			rule.Help = &sarifText{Text: "Suggested esops commands: " + strings.Join(cmds, "; ")}
		}
		if r.Rule.Severity != findings.SeverityUnknown {
			rule.DefaultConfiguration = &sarifRuleDefaults{Level: sarifLevel(r.Rule.Severity)}
		}
		idx[r.RuleID] = len(rules)
		rules = append(rules, rule)
	}
	return rules, idx
}

func sarifResults(results []engine.RuleResult, idx map[string]int, opts Options, dialect string) []sarifResult {
	out := make([]sarifResult, 0, len(results))
	for _, r := range results {
		if opts.Quiet && (r.Status == engine.RuleStatusPass || r.Status == engine.RuleStatusSkipped) {
			continue
		}
		out = append(out, sarifResultOf(r, idx[r.RuleID], dialect))
	}
	return out
}

func sarifResultOf(r engine.RuleResult, ruleIdx int, dialect string) sarifResult {
	res := sarifResult{
		RuleID:    r.RuleID,
		RuleIndex: ruleIdx,
		Kind:      sarifKind(r.Status),
	}
	switch r.Status {
	case engine.RuleStatusFail:
		if r.Finding != nil {
			res.Level = sarifLevel(r.Finding.Severity)
			res.Message.Text = r.Finding.Message
			if isActiveWaiver(r.Finding) {
				res.Suppressions = []sarifSuppression{{
					Kind:          "external",
					Status:        "accepted",
					Justification: r.Finding.Suppression.Justification,
				}}
			} else if isBaselined(r.Finding) {
				// A baseline-matched finding is preexisting per the
				// operator's recorded scan. Map it onto a SARIF
				// suppression so GitHub code-scanning and similar
				// consumers stop double-counting it as a fresh
				// failure. underReview (rather than accepted) reflects
				// the semantics: "this was here before, schedule a
				// fix" — not "this is permanently excused".
				justification := "matched operator-supplied baseline"
				if src := r.Finding.Baseline.Source; src != "" {
					justification = "matched baseline " + src
				}
				res.Suppressions = []sarifSuppression{{
					Kind:          "external",
					Status:        "underReview",
					Justification: justification,
				}}
			}
			// partialFingerprints carries the canonical baseline match
			// key so a future `scan --baseline previous.sarif` round-
			// trips the (rule_id, dialect, target) tuple precisely.
			// SARIF defines partialFingerprints exactly for this case
			// (stable cross-scan identity), so consumers ignore the
			// extra keys without complaint.
			res.PartialFingerprints = map[string]string{
				"rule_id": r.RuleID,
				"dialect": dialect,
			}
		}
	case engine.RuleStatusSkipped:
		res.Message.Text = r.SkipReason
	case engine.RuleStatusError:
		res.Level = "error"
		if r.Err != nil {
			res.Message.Text = r.Err.Error()
		}
	case engine.RuleStatusPass:
		res.Message.Text = fmt.Sprintf("Rule %s passed against %s.", r.RuleID, dialect)
	}
	if res.Message.Text == "" {
		res.Message.Text = r.RuleID
	}
	return res
}

func sarifKind(s engine.RuleStatus) string {
	switch s {
	case engine.RuleStatusPass:
		return "pass"
	case engine.RuleStatusFail:
		return "fail"
	case engine.RuleStatusSkipped:
		return "notApplicable"
	case engine.RuleStatusError:
		return "review"
	default:
		return ""
	}
}

func sarifLevel(s findings.Severity) string {
	switch s {
	case findings.SeverityInfo:
		return "note"
	case findings.SeverityWarn:
		return "warning"
	case findings.SeverityError, findings.SeverityCritical:
		return "error"
	default:
		return "none"
	}
}

// sarifInvocFromHeader builds an invocation block populated with the
// scan's StartTimeUtc/EndTimeUtc when the caller filled in the
// Header's StartedAt. SARIF wants RFC3339 with a literal "Z" suffix
// (UTC offset = 0); time.RFC3339 with .UTC() satisfies that. Headers
// without a StartedAt (legacy hand-built test data) leave both fields
// empty so they elide cleanly.
func sarifInvocFromHeader(h Header, success bool) sarifInvoc {
	inv := sarifInvoc{ExecutionSuccessful: success}
	if !h.StartedAt.IsZero() {
		start := h.StartedAt.UTC()
		inv.StartTimeUtc = start.Format(time.RFC3339)
		if h.Duration > 0 {
			inv.EndTimeUtc = start.Add(h.Duration).Format(time.RFC3339)
		}
	}
	return inv
}

func anyErrored(results []engine.RuleResult) bool {
	for _, r := range results {
		if r.Status == engine.RuleStatusError {
			return true
		}
	}
	return false
}
