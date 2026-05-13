package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/esops-dev/esops-doctor/internal/exit"
	"github.com/esops-dev/esops-doctor/internal/rules"
)

// explainFindingCommand pairs `explain` (rule definition) with the
// cluster-side context that fired a finding. Triage today requires the
// operator to cross-reference an explain block with a scan report by
// eye; this command joins them so one invocation produces the full
// "what fired, why, and what to do" surface.
//
// --from PATH is a previous scan in doctor JSON form (the json
// renderer's output). SARIF is intentionally out of scope here — its
// shape is sparser and doesn't carry the rule metadata, message,
// and remediation in a single result the way doctor's JSON does.
func explainFindingCommand() *cli.Command {
	return &cli.Command{
		Name:      "explain-finding",
		Usage:     "Print a rule's explain block plus the cluster-side context that fired it",
		ArgsUsage: "RULE_ID",
		Description: "Reads a previous scan from --from PATH (doctor JSON only — produced\n" +
			"by `esops-doctor scan --output json`), finds the result for RULE_ID,\n" +
			"and prints the rule's explain block alongside the runtime context\n" +
			"(message, severity, duration, fingerprint, suppression, baseline).\n\n" +
			"Use `explain RULE_ID` for the static rule definition without a\n" +
			"scan attached.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "from",
				Usage:    "Path to a previous scan in doctor JSON form (required; single- or multi-cluster shape)",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "target",
				Usage: "When --from is a multi-cluster scan, restrict lookup to this target label (URL or context name)",
			},
			&cli.StringFlag{
				Name:  "rules-dir",
				Usage: "Additional rule directory layered over the embedded catalog when looking up the rule",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runExplainFinding(ctx, cmd, cmdWriter(cmd))
		},
	}
}

// scanResultRow is the subset of report.Document.Results that
// explain-finding consumes. Inlined (rather than importing
// report.Document) so the cli stays free of a transitive coupling
// from `explain-finding` to the report layer's struct shape.
type scanResultRow struct {
	RuleID      string            `json:"rule_id"`
	Status      string            `json:"status"`
	Severity    string            `json:"severity"`
	Message     string            `json:"message"`
	DurationMs  int64             `json:"duration_ms"`
	Fingerprint *scanFingerprint  `json:"fingerprint"`
	Remediation *scanRemediation  `json:"remediation"`
	Suppression *scanSuppression  `json:"suppression"`
	Baseline    *scanBaselineHint `json:"baseline"`
	Probe       string            `json:"probe"`
	Category    string            `json:"category"`
	Name        string            `json:"name"`
}

type scanFingerprint struct {
	RuleID  string `json:"rule_id"`
	Dialect string `json:"dialect"`
	Target  string `json:"target,omitempty"`
}

type scanRemediation struct {
	Command       string   `json:"command,omitempty"`
	DocURL        string   `json:"doc_url,omitempty"`
	EsopsCommands []string `json:"esops_commands,omitempty"`
}

type scanSuppression struct {
	Justification string `json:"justification"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	Expired       bool   `json:"expired"`
	Source        string `json:"source,omitempty"`
}

type scanBaselineHint struct {
	Source string `json:"source,omitempty"`
}

type scanDocument struct {
	SchemaVersion int             `json:"schema_version"`
	Cluster       scanClusterInfo `json:"cluster"`
	Results       []scanResultRow `json:"results"`
}

type scanClusterInfo struct {
	Name    string `json:"name"`
	Dialect string `json:"dialect"`
	Version string `json:"version"`
}

// fleetDocument is the multi-cluster JSON shape (`scan --targets a,b
// --output json` produces it). The per-cluster Document lives inside
// each clusters[] entry. Inlined here for the same reason scanDocument
// is — explain-finding doesn't need a transitive coupling to the
// report package's struct shape.
type fleetDocument struct {
	SchemaVersion int              `json:"schema_version"`
	Clusters      []fleetClusterEntry `json:"clusters"`
}

type fleetClusterEntry struct {
	Label    string        `json:"label"`
	Document *scanDocument `json:"document"`
}

func runExplainFinding(_ context.Context, cmd *cli.Command, stdout io.Writer) error {
	if cmd.NArg() == 0 {
		return exit.Usage("explain-finding requires exactly one RULE_ID argument")
	}
	if cmd.NArg() > 1 {
		return exit.Usage("explain-finding accepts exactly one RULE_ID argument; got %d", cmd.NArg())
	}
	id := strings.TrimSpace(cmd.Args().First())
	if id == "" {
		return exit.Usage("explain-finding requires a non-empty RULE_ID argument")
	}

	path := strings.TrimSpace(cmd.String("from"))
	if path == "" {
		return exit.Usage("--from PATH is required")
	}
	cleanPath := filepath.Clean(path)
	raw, err := os.ReadFile(cleanPath) // #nosec G304 -- path supplied by operator on the CLI
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return exit.Usage("--from %q does not exist", path)
		}
		return fmt.Errorf("reading scan file %q: %w", path, err)
	}

	target := strings.TrimSpace(cmd.String("target"))
	doc, err := resolveScanDocument(raw, id, target, path)
	if err != nil {
		return err
	}

	row, ok := findResultRow(doc.Results, id)
	if !ok {
		return exit.Usage("rule %q is not present in the scan results of %q (run `esops-doctor explain %s` for the static definition)", id, path, id)
	}

	cat, err := loadLayeredCatalog(cmd.String("rules-dir"))
	if err != nil {
		return err
	}
	rule, ok := lookupRule(cat, id)
	if !ok {
		// The catalog may have been edited since the scan ran. Render
		// the runtime context anyway — the operator still wants the
		// triage data — and surface the catalog mismatch so they
		// don't think the rule is silently gone.
		return renderExplainFinding(stdout, rules.Rule{ID: id}, row, doc, "rule not found in current catalog (scan predates the change?)")
	}
	return renderExplainFinding(stdout, rule, row, doc, "")
}

// resolveScanDocument picks the right cluster slice out of --from.
// A single-cluster scan returns its document directly. A multi-cluster
// (fleet) scan either:
//
//   - returns the named target's document when --target matches one
//     entry's label;
//   - returns the only cluster that contains a matching rule when
//     --target is unset and exactly one cluster carries the finding;
//   - returns a clear usage error listing the candidate targets when
//     the choice is ambiguous.
//
// The shape detection is deliberate: a multi-cluster doc carries
// clusters[] at the top level, a single-cluster doc carries
// results[]. Both share schema_version=1 so the field-presence test
// is the discriminator.
func resolveScanDocument(raw []byte, ruleID, target, path string) (scanDocument, error) {
	if doc, ok := tryParseFleet(raw); ok {
		return resolveFleetClusterForRule(doc, ruleID, target, path)
	}
	doc, err := parseScanDocument(raw)
	if err != nil {
		return scanDocument{}, exit.Usage("--from %q is not a doctor JSON scan: %s", path, err.Error())
	}
	if target != "" {
		return scanDocument{}, exit.Usage("--target is only meaningful when --from is a multi-cluster scan")
	}
	return doc, nil
}

// tryParseFleet attempts to decode raw as a fleet document. Returns
// (doc, true) when the JSON is valid AND carries a non-empty
// clusters[] array — the load-bearing signal for the multi-cluster
// shape. Decode failures fall through to the single-cluster path so a
// stray syntax error still surfaces as a JSON error there.
func tryParseFleet(raw []byte) (fleetDocument, bool) {
	var doc fleetDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fleetDocument{}, false
	}
	if len(doc.Clusters) == 0 {
		return fleetDocument{}, false
	}
	return doc, true
}

// resolveFleetClusterForRule applies the --target / auto-pick rules
// described in resolveScanDocument's comment.
func resolveFleetClusterForRule(doc fleetDocument, ruleID, target, path string) (scanDocument, error) {
	if target != "" {
		for _, c := range doc.Clusters {
			if c.Label == target {
				if c.Document == nil {
					return scanDocument{}, exit.Usage("--target %q matched a cluster but the connect failed; nothing to explain", target)
				}
				return *c.Document, nil
			}
		}
		return scanDocument{}, exit.Usage("--target %q not present in --from %q (available: %s)",
			target, path, strings.Join(fleetTargetLabels(doc), ", "))
	}

	var matches []string
	var hit *scanDocument
	for i := range doc.Clusters {
		c := doc.Clusters[i]
		if c.Document == nil {
			continue
		}
		if _, ok := findResultRow(c.Document.Results, ruleID); ok {
			matches = append(matches, c.Label)
			if hit == nil {
				hit = c.Document
			}
		}
	}
	switch len(matches) {
	case 0:
		return scanDocument{}, exit.Usage("rule %q is not present in any cluster in --from %q (run `esops-doctor explain %s` for the static definition)", ruleID, path, ruleID)
	case 1:
		return *hit, nil
	default:
		return scanDocument{}, exit.Usage("rule %q fired on %d clusters in --from %q; pass --target to disambiguate (available: %s)",
			ruleID, len(matches), path, strings.Join(matches, ", "))
	}
}

// fleetTargetLabels returns the label of every cluster slot in the
// fleet document, in declaration order. Used by the --target
// mismatch message so an operator sees the exact strings doctor would
// match against.
func fleetTargetLabels(doc fleetDocument) []string {
	out := make([]string, 0, len(doc.Clusters))
	for _, c := range doc.Clusters {
		out = append(out, c.Label)
	}
	return out
}

// parseScanDocument tolerates the doctor JSON shape (schema_version 1).
// SARIF is intentionally rejected here — its results carry partial
// fingerprints but neither the rule metadata nor the message in the
// same place; the operator-facing trade-off is "use JSON for triage
// round-trips, SARIF for upload to code-scanning".
func parseScanDocument(raw []byte) (scanDocument, error) {
	var doc scanDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return scanDocument{}, fmt.Errorf("not valid JSON: %w", err)
	}
	if doc.SchemaVersion == 0 {
		return scanDocument{}, fmt.Errorf("missing schema_version (is this SARIF? explain-finding accepts doctor JSON only)")
	}
	return doc, nil
}

// findResultRow returns the row in results whose rule_id matches id.
// Falls back to a case-sensitive match only — rule IDs are part of
// the wire contract and a typo'd lookup should fail loud.
func findResultRow(results []scanResultRow, id string) (scanResultRow, bool) {
	for _, r := range results {
		if r.RuleID == id {
			return r, true
		}
	}
	return scanResultRow{}, false
}

// renderExplainFinding emits the joined view: the rule's static
// explain block first (same shape as `explain RULE_ID`), then the
// runtime context (severity, message, fingerprint, suppression,
// baseline, durations). catalogNote, when non-empty, is appended at
// the top so the operator sees catalog/scan drift inline rather than
// having to spot a missing description silently.
func renderExplainFinding(w io.Writer, rule rules.Rule, row scanResultRow, doc scanDocument, catalogNote string) error {
	var b strings.Builder
	if catalogNote != "" {
		fmt.Fprintf(&b, "Note: %s\n\n", catalogNote)
	}

	if rule.ID != "" && rule.Name != "" {
		if err := renderExplainText(&b, rule, rule.ID); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(&b, "%s\n  (rule not found in current catalog)\n", row.RuleID)
	}

	b.WriteString("\nRuntime context (from --from):\n")
	if doc.Cluster.Name != "" || doc.Cluster.Dialect != "" {
		fmt.Fprintf(&b, "  cluster:     %s (%s %s)\n",
			strDefault(doc.Cluster.Name, "(no name)"),
			strDefault(doc.Cluster.Dialect, "?"),
			doc.Cluster.Version)
	}
	fmt.Fprintf(&b, "  status:      %s\n", strDefault(row.Status, "(unknown)"))
	if row.Severity != "" {
		fmt.Fprintf(&b, "  severity:    %s\n", row.Severity)
	}
	if row.Message != "" {
		fmt.Fprintf(&b, "  message:     %s\n", oneLineForExplain(row.Message))
	}
	if row.DurationMs > 0 {
		fmt.Fprintf(&b, "  duration:    %dms\n", row.DurationMs)
	}
	if row.Fingerprint != nil {
		fmt.Fprintf(&b, "  fingerprint: rule_id=%s dialect=%s",
			row.Fingerprint.RuleID, row.Fingerprint.Dialect)
		if row.Fingerprint.Target != "" {
			fmt.Fprintf(&b, " target=%s", row.Fingerprint.Target)
		}
		b.WriteString("\n")
	}
	if sup := row.Suppression; sup != nil {
		fmt.Fprintf(&b, "  waiver:      %s", sup.Justification)
		if sup.ExpiresAt != "" {
			fmt.Fprintf(&b, " (expires %s%s)", sup.ExpiresAt, expiredSuffix(sup.Expired))
		}
		if sup.Source != "" {
			fmt.Fprintf(&b, " [source: %s]", sup.Source)
		}
		b.WriteString("\n")
	}
	if row.Baseline != nil && row.Baseline.Source != "" {
		fmt.Fprintf(&b, "  baseline:    %s\n", row.Baseline.Source)
	}

	if rem := row.Remediation; rem != nil && (rem.Command != "" || rem.DocURL != "" || len(rem.EsopsCommands) > 0) {
		b.WriteString("\nRemediation (from finding):\n")
		if rem.Command != "" {
			fmt.Fprintf(&b, "  command: %s\n", rem.Command)
		}
		if rem.DocURL != "" {
			fmt.Fprintf(&b, "  doc_url: %s\n", rem.DocURL)
		}
		if len(rem.EsopsCommands) > 0 {
			b.WriteString("  esops_commands:\n")
			for _, cmd := range rem.EsopsCommands {
				fmt.Fprintf(&b, "    - %s\n", cmd)
			}
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// expiredSuffix marks an expired waiver inline so the operator does
// not have to compare the date to today's clock by eye.
func expiredSuffix(expired bool) string {
	if expired {
		return "; EXPIRED"
	}
	return ""
}

// strDefault returns def when s is empty (after trim). Lets the
// renderer keep a stable shape across results that omit
// optional fields.
func strDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// oneLineForExplain collapses a multi-line finding message to a
// single line so the explain-finding block stays aligned. Newlines
// become " | "; long messages render in full so triage doesn't have
// to re-open the source scan.
func oneLineForExplain(s string) string {
	s = strings.ReplaceAll(s, "\n", " | ")
	s = strings.ReplaceAll(s, "\t", " ")
	return s
}
