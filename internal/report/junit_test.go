package report

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/findings"
)

// junitParsed is a parsing-only twin of the renderer's struct shape.
// Defining it locally keeps tests asserting against the wire format
// rather than the renderer's internal types — a struct rename can't
// silently break consumers.
type junitParsed struct {
	XMLName  xml.Name      `xml:"testsuites"`
	Name     string        `xml:"name,attr"`
	Tests    int           `xml:"tests,attr"`
	Failures int           `xml:"failures,attr"`
	Errors   int           `xml:"errors,attr"`
	Skipped  int           `xml:"skipped,attr"`
	Time     string        `xml:"time,attr"`
	Suites   []parsedSuite `xml:"testsuite"`
}

type parsedSuite struct {
	Name      string       `xml:"name,attr"`
	Tests     int          `xml:"tests,attr"`
	Failures  int          `xml:"failures,attr"`
	Errors    int          `xml:"errors,attr"`
	Skipped   int          `xml:"skipped,attr"`
	Time      string       `xml:"time,attr"`
	Hostname  string       `xml:"hostname,attr"`
	TestCases []parsedCase `xml:"testcase"`
}

type parsedCase struct {
	Name      string         `xml:"name,attr"`
	ClassName string         `xml:"classname,attr"`
	Time      string         `xml:"time,attr"`
	Failure   *parsedFailure `xml:"failure,omitempty"`
	Error     *parsedError   `xml:"error,omitempty"`
	Skipped   *parsedSkipped `xml:"skipped,omitempty"`
}

type parsedFailure struct {
	Type    string `xml:"type,attr"`
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

type parsedError struct {
	Type    string `xml:"type,attr"`
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

type parsedSkipped struct {
	Message string `xml:"message,attr"`
}

func decodeJUnit(t *testing.T, b []byte) junitParsed {
	t.Helper()
	var d junitParsed
	if err := xml.Unmarshal(b, &d); err != nil {
		t.Fatalf("decode junit: %v\n%s", err, b)
	}
	return d
}

func TestJUnitShape(t *testing.T) {
	var buf bytes.Buffer
	if err := JUnit(&buf, sampleHeader(), sampleResults(), Options{}); err != nil {
		t.Fatalf("JUnit: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, `<?xml version="1.0"`) {
		t.Errorf("output should start with XML header; got %.40q", out)
	}
	d := decodeJUnit(t, buf.Bytes())

	if d.Tests != 4 || d.Failures != 1 || d.Errors != 1 || d.Skipped != 1 {
		t.Errorf("testsuites attrs = %+v", d)
	}
	if len(d.Suites) != 1 {
		t.Fatalf("expected 1 testsuite, got %d", len(d.Suites))
	}
	suite := d.Suites[0]
	if suite.Tests != 4 || suite.Failures != 1 || suite.Errors != 1 || suite.Skipped != 1 {
		t.Errorf("testsuite attrs = %+v", suite)
	}
	if suite.Hostname != "prod-eu" {
		t.Errorf("testsuite.hostname = %q, want cluster name", suite.Hostname)
	}
	if len(suite.TestCases) != 4 {
		t.Fatalf("expected 4 testcases, got %d", len(suite.TestCases))
	}

	byName := map[string]parsedCase{}
	for _, c := range suite.TestCases {
		byName[c.Name] = c
	}
	for _, c := range suite.TestCases {
		if c.ClassName != "esops-doctor" {
			t.Errorf("testcase %s classname = %q, want esops-doctor", c.Name, c.ClassName)
		}
	}

	fail := byName["heap_size"]
	if fail.Failure == nil {
		t.Fatal("heap_size testcase should carry <failure>")
	}
	if fail.Failure.Type != "critical" {
		t.Errorf("failure.type = %q, want critical", fail.Failure.Type)
	}
	if !strings.Contains(fail.Failure.Message, "Heap misconfigured") {
		t.Errorf("failure.message = %q", fail.Failure.Message)
	}

	skip := byName["ilm_policy"]
	if skip.Skipped == nil {
		t.Fatal("ilm_policy testcase should carry <skipped>")
	}
	if !strings.Contains(skip.Skipped.Message, "opensearch") {
		t.Errorf("skipped.message = %q", skip.Skipped.Message)
	}

	errCase := byName["broken"]
	if errCase.Error == nil {
		t.Fatal("broken testcase should carry <error>")
	}
	if !strings.Contains(errCase.Error.Message, "no such key: jvm") {
		t.Errorf("error.message = %q", errCase.Error.Message)
	}

	pass := byName["passes"]
	if pass.Failure != nil || pass.Error != nil || pass.Skipped != nil {
		t.Errorf("pass testcase should carry no child element; got %+v", pass)
	}
}

func TestJUnitSummaryOnlyDropsTestcases(t *testing.T) {
	var buf bytes.Buffer
	if err := JUnit(&buf, sampleHeader(), sampleResults(), Options{SummaryOnly: true}); err != nil {
		t.Fatalf("JUnit: %v", err)
	}
	d := decodeJUnit(t, buf.Bytes())
	if d.Tests != 4 || d.Failures != 1 {
		t.Errorf("summary counts must survive --summary-only; got %+v", d)
	}
	if len(d.Suites) != 1 {
		t.Fatalf("expected 1 suite, got %d", len(d.Suites))
	}
	if len(d.Suites[0].TestCases) != 0 {
		t.Errorf("--summary-only should drop testcases; got %d", len(d.Suites[0].TestCases))
	}
}

func TestJUnitQuietDropsPassAndSkipped(t *testing.T) {
	var buf bytes.Buffer
	if err := JUnit(&buf, sampleHeader(), sampleResults(), Options{Quiet: true}); err != nil {
		t.Fatalf("JUnit: %v", err)
	}
	d := decodeJUnit(t, buf.Bytes())
	suite := d.Suites[0]
	for _, c := range suite.TestCases {
		if c.Name == "passes" || c.Name == "ilm_policy" {
			t.Errorf("--quiet should drop pass+skipped testcase %q", c.Name)
		}
	}
	if d.Tests != 4 || d.Skipped != 1 {
		t.Errorf("summary counts must reflect full set; got %+v", d)
	}
}

// TestJUnitActiveWaiverRendersAsSkippedNotFailure encodes the contract
// for CI consumers: a waived failing rule comes out as <skipped>, not
// <failure>, so Jenkins/GitLab don't count it toward "build broken".
// The justification rides in the message attribute. Expired waivers
// stay as <failure> because the suppression failed and the row should
// re-surface the loud pre-existing problem.
func TestJUnitActiveWaiverRendersAsSkippedNotFailure(t *testing.T) {
	live := failResult("a", "x", findings.SeverityCritical, "live")
	waived := failResult("b", "x", findings.SeverityCritical, "waived")
	waived.Finding.Suppression = &findings.Suppression{Justification: "approved"}
	expired := failResult("c", "x", findings.SeverityCritical, "[waiver expired 2024-01-01] msg")
	expired.Finding.Suppression = &findings.Suppression{Justification: "lapsed", Expired: true}

	var buf bytes.Buffer
	if err := JUnit(&buf, Header{Dialect: "elasticsearch"},
		[]engine.RuleResult{live, waived, expired}, Options{}); err != nil {
		t.Fatalf("JUnit: %v", err)
	}
	d := decodeJUnit(t, buf.Bytes())
	suite := d.Suites[0]
	cases := map[string]parsedCase{}
	for _, c := range suite.TestCases {
		cases[c.Name] = c
	}

	if cases["a"].Failure == nil || cases["a"].Skipped != nil {
		t.Errorf("live row should be <failure>; got %+v", cases["a"])
	}
	if cases["b"].Skipped == nil || cases["b"].Failure != nil {
		t.Errorf("active waiver row should be <skipped>; got %+v", cases["b"])
	}
	if !strings.Contains(cases["b"].Skipped.Message, "approved") {
		t.Errorf("waiver justification should appear in skipped.message; got %q",
			cases["b"].Skipped.Message)
	}
	if cases["c"].Failure == nil || cases["c"].Skipped != nil {
		t.Errorf("expired-waiver row should still be <failure>; got %+v", cases["c"])
	}

	// Suite-level counts: live + expired are failures; waived counts as
	// skipped so dashboards don't double-count it.
	if suite.Failures != 2 || suite.Skipped != 1 {
		t.Errorf("suite counts wrong: failures=%d skipped=%d (want 2/1)",
			suite.Failures, suite.Skipped)
	}
}

// TestJUnitEscapesAttributeContent guards the XML escaping path: a
// rule message with `"` and `<` must come out well-formed so a
// downstream JUnit parser doesn't fail at attribute-boundary chars.
// encoding/xml does the escaping; this test catches a regression
// where someone bypasses it (e.g. fmt.Fprintf into raw bytes).
func TestJUnitEscapesAttributeContent(t *testing.T) {
	results := []engine.RuleResult{
		failResult("rule", "cat", findings.SeverityWarn, `dialect "x" <bad>`),
	}
	var buf bytes.Buffer
	if err := JUnit(&buf, Header{Dialect: "elasticsearch"}, results, Options{}); err != nil {
		t.Fatalf("JUnit: %v", err)
	}
	if strings.Contains(buf.String(), `"x" <bad>`) {
		t.Errorf("attribute content should be escaped on the wire; got:\n%s", buf.String())
	}
	d := decodeJUnit(t, buf.Bytes())
	got := d.Suites[0].TestCases[0].Failure.Message
	if got != `dialect "x" <bad>` {
		t.Errorf("round-tripped message = %q", got)
	}
}
