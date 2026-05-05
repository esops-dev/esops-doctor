package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

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
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name,omitempty"`
	ShortDescription     *sarifText         `json:"shortDescription,omitempty"`
	FullDescription      *sarifText         `json:"fullDescription,omitempty"`
	HelpURI              string             `json:"helpUri,omitempty"`
	DefaultConfiguration *sarifRuleDefaults `json:"defaultConfiguration,omitempty"`
}

type sarifRuleDefaults struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string    `json:"ruleId"`
	RuleIndex int       `json:"ruleIndex"`
	Level     string    `json:"level,omitempty"`
	Kind      string    `json:"kind,omitempty"`
	Message   sarifText `json:"message"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifInvoc struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

func buildSarif(h Header, results []engine.RuleResult, opts Options) sarifDoc {
	rules, ruleIndex := sarifRules(results)
	doc := sarifDoc{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "esops-doctor",
				Version:        version.Version,
				InformationURI: sarifToolURI,
				Rules:          rules,
			}},
			Results: []sarifResult{},
			Invocs:  []sarifInvoc{{ExecutionSuccessful: !anyErrored(results)}},
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

func anyErrored(results []engine.RuleResult) bool {
	for _, r := range results {
		if r.Status == engine.RuleStatusError {
			return true
		}
	}
	return false
}
