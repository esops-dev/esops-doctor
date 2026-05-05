package report

import (
	"encoding/xml"
	"fmt"
	"io"

	"github.com/esops-dev/esops-doctor/internal/engine"
)

// JUnit writes the report as JUnit XML — one <testcase> per rule under
// a single <testsuite> wrapped in <testsuites>. The schema is the
// de-facto Jenkins/CI variant; encoding/xml escapes attribute and
// element text so message bodies with `"` or `<` round-trip safely.
//
// Status mapping:
//
//	fail    → <testcase><failure type=severity message=msg>msg</failure>
//	skipped → <testcase><skipped message=reason/>
//	error   → <testcase><error message=err>err</error>
//	pass    → <testcase/> (empty)
//
// opts.SummaryOnly drops every <testcase> child, leaving only the
// counts on <testsuites>/<testsuite>. opts.Quiet drops pass + skipped
// testcases (matching the JSON/YAML/SARIF contract).
func JUnit(w io.Writer, h Header, results []engine.RuleResult, opts Options) error {
	doc := buildJUnit(h, results, opts)
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return fmt.Errorf("writing junit header: %w", err)
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encoding junit report: %w", err)
	}
	if err := enc.Flush(); err != nil {
		return fmt.Errorf("flushing junit encoder: %w", err)
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		return fmt.Errorf("writing junit trailer: %w", err)
	}
	return nil
}

const junitClassName = "esops-doctor"

type junitTestSuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Errors   int              `xml:"errors,attr"`
	Skipped  int              `xml:"skipped,attr"`
	Time     string           `xml:"time,attr"`
	Suites   []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Skipped   int             `xml:"skipped,attr"`
	Time      string          `xml:"time,attr"`
	Hostname  string          `xml:"hostname,attr,omitempty"`
	TestCases []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name      string         `xml:"name,attr"`
	ClassName string         `xml:"classname,attr"`
	Time      string         `xml:"time,attr"`
	Failure   *junitFailure  `xml:"failure,omitempty"`
	Error     *junitErrorTag `xml:"error,omitempty"`
	Skipped   *junitSkipped  `xml:"skipped,omitempty"`
}

type junitFailure struct {
	Type    string `xml:"type,attr,omitempty"`
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

type junitErrorTag struct {
	Type    string `xml:"type,attr,omitempty"`
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

func buildJUnit(h Header, results []engine.RuleResult, opts Options) junitTestSuites {
	c := classify(results)
	failures := c.critical + c.error + c.warn + c.info
	suite := junitTestSuite{
		Name:     junitClassName,
		Tests:    len(results),
		Failures: failures,
		Errors:   c.errored,
		Skipped:  c.skipped,
		Time:     formatJUnitSeconds(h.Duration.Seconds()),
		Hostname: h.ClusterName,
	}
	if !opts.SummaryOnly {
		suite.TestCases = junitTestCases(results, opts)
	}
	return junitTestSuites{
		Name:     junitClassName,
		Tests:    len(results),
		Failures: failures,
		Errors:   c.errored,
		Skipped:  c.skipped,
		Time:     formatJUnitSeconds(h.Duration.Seconds()),
		Suites:   []junitTestSuite{suite},
	}
}

func junitTestCases(results []engine.RuleResult, opts Options) []junitTestCase {
	out := make([]junitTestCase, 0, len(results))
	for _, r := range results {
		if opts.Quiet && (r.Status == engine.RuleStatusPass || r.Status == engine.RuleStatusSkipped) {
			continue
		}
		tc := junitTestCase{
			Name:      r.RuleID,
			ClassName: junitClassName,
			Time:      formatJUnitSeconds(r.Duration.Seconds()),
		}
		switch r.Status {
		case engine.RuleStatusFail:
			if r.Finding != nil {
				tc.Failure = &junitFailure{
					Type:    r.Finding.Severity.String(),
					Message: r.Finding.Message,
					Body:    r.Finding.Message,
				}
			} else {
				tc.Failure = &junitFailure{Message: r.RuleID}
			}
		case engine.RuleStatusError:
			msg := "evaluation error"
			if r.Err != nil {
				msg = r.Err.Error()
			}
			tc.Error = &junitErrorTag{Type: "evaluation", Message: msg, Body: msg}
		case engine.RuleStatusSkipped:
			tc.Skipped = &junitSkipped{Message: r.SkipReason}
		}
		out = append(out, tc)
	}
	return out
}

// formatJUnitSeconds renders a duration in seconds with three decimals,
// the format Jenkins and most JUnit consumers expect. A zero duration
// renders as "0.000" rather than "0" so the attribute is well-formed.
func formatJUnitSeconds(s float64) string {
	return fmt.Sprintf("%.3f", s)
}
