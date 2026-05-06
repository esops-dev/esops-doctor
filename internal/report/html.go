package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"sync"

	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/findings"
)

//go:embed html.tmpl
var htmlTemplate string

// HTML writes the report as a single self-contained HTML document.
// The page carries inline CSS and JS so it works offline and from a
// file:// URL — useful for review meetings and ticket attachments.
//
// The template is parsed once on first use and cached. html/template
// does context-aware escaping for every interpolation, so a rule
// message containing `<script>` cannot escape the data column.
//
// Honours opts.SummaryOnly (drops the results table) and opts.Quiet
// (drops pass + skipped rows from results) the same way the other
// renderers do.
func HTML(w io.Writer, h Header, results []engine.RuleResult, opts Options) error {
	tmpl, err := parsedHTMLTemplate()
	if err != nil {
		return err
	}
	doc := BuildDocument(h, results, opts)
	if err := tmpl.Execute(w, doc); err != nil {
		return fmt.Errorf("rendering html report: %w", err)
	}
	return nil
}

var (
	htmlTmplCache    *template.Template
	htmlTmplCacheErr error
	htmlTmplCacheDo  sync.Once
)

// parsedHTMLTemplate parses the embedded template once on first call
// and caches the result for the rest of the process. sync.Once makes
// the cache safe for concurrent test runs (and any future caller that
// renders reports in parallel); a parse error is sticky and returned
// to every subsequent caller.
func parsedHTMLTemplate() (*template.Template, error) {
	htmlTmplCacheDo.Do(func() {
		t, err := template.New("report").Funcs(template.FuncMap{
			"severityRank":  severityRank,
			"statusRank":    statusRank,
			"displayStatus": displayStatus,
		}).Parse(htmlTemplate)
		if err != nil {
			htmlTmplCacheErr = fmt.Errorf("parsing html template: %w", err)
			return
		}
		htmlTmplCache = t
	})
	return htmlTmplCache, htmlTmplCacheErr
}

// severityRank maps the severity string to a numeric value so the
// per-cell data-sort-value attribute can drive the JS sort by urgency
// rather than alphabetical order. Higher number = more urgent. Routes
// through findings.ParseSeverity + Severity.Rank so the ladder lives
// in one place; an unparsed string maps to SeverityUnknown (rank 0).
func severityRank(s string) int {
	sev, _ := findings.ParseSeverity(s)
	return sev.Rank()
}

// statusRank ranks status strings so the JS sort surfaces fails first,
// then errors, then waived, then skipped, then passes — matching the
// order an operator triages findings on the page. Waived sits between
// errors and skipped because a waived row still warrants a glance
// (the suppression should be reviewed) but doesn't demand action.
func statusRank(s string) int {
	switch s {
	case "fail":
		return 4
	case "error":
		return 3
	case "waived":
		return 2
	case "skipped":
		return 1
	case "pass":
		return 0
	default:
		return -1
	}
}

// displayStatus is the visual override applied to active-waiver rows:
// the wire status stays "fail" (consumers parsing the JSON/YAML schema
// see the truth — the rule failed and was suppressed by an operator
// waiver) but the HTML page surfaces "waived" so a reviewer can filter
// or sort by suppression state directly. Expired waivers fall back to
// "fail" because the suppression failed and the finding is live.
func displayStatus(r Result) string {
	if r.Status == "fail" && r.Suppression != nil && !r.Suppression.Expired {
		return "waived"
	}
	return r.Status
}
