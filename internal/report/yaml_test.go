package report

import (
	"bytes"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

// decodeYAML parses the renderer output back into a Document so each
// test asserts against parsed values rather than substring-matching
// the rendered bytes.
func decodeYAML(t *testing.T, b []byte) Document {
	t.Helper()
	var d Document
	if err := yaml.Unmarshal(b, &d); err != nil {
		t.Fatalf("decode: %v\n%s", err, b)
	}
	return d
}

func TestYAMLShape(t *testing.T) {
	var buf bytes.Buffer
	if err := YAML(&buf, sampleHeader(), sampleResults(), Options{}); err != nil {
		t.Fatalf("YAML: %v", err)
	}
	d := decodeYAML(t, buf.Bytes())

	if d.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %d, want %d", d.SchemaVersion, SchemaVersion)
	}
	if d.Cluster.Dialect != "elasticsearch" || d.Cluster.Name != "prod-eu" {
		t.Errorf("cluster block = %+v", d.Cluster)
	}
	if d.Summary.Failed != 1 || d.Summary.BySeverity.Critical != 1 {
		t.Errorf("summary = %+v", d.Summary)
	}
	if len(d.Results) != 4 {
		t.Errorf("results length = %d, want 4", len(d.Results))
	}

	// Field naming is the contract — the json renderer's tests already
	// guard the per-field shape, so YAML's job here is to match the
	// same wire names. A quick substring sweep on the raw output is
	// enough to catch a tag-name regression.
	out := buf.String()
	for _, want := range []string{
		"schema_version: 1",
		"dialect: elasticsearch",
		"duration_ms:",
		"by_severity:",
		"rule_id: heap_size",
		"status: fail",
		"skip_reason:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("yaml output missing %q\nfull output:\n%s", want, out)
		}
	}
}

func TestYAMLSummaryOnlyDropsResults(t *testing.T) {
	var buf bytes.Buffer
	if err := YAML(&buf, sampleHeader(), sampleResults(), Options{SummaryOnly: true}); err != nil {
		t.Fatalf("YAML: %v", err)
	}
	d := decodeYAML(t, buf.Bytes())
	if len(d.Results) != 0 {
		t.Errorf("--summary-only should drop results; got %d", len(d.Results))
	}
	if d.Summary.Passed != 1 {
		t.Errorf("summary must survive --summary-only; got %+v", d.Summary)
	}
	if strings.Contains(buf.String(), "results:") {
		t.Errorf("rendered output should not contain a results: key under --summary-only; got:\n%s", buf.String())
	}
}

func TestYAMLQuietDropsPassAndSkipped(t *testing.T) {
	var buf bytes.Buffer
	if err := YAML(&buf, sampleHeader(), sampleResults(), Options{Quiet: true}); err != nil {
		t.Fatalf("YAML: %v", err)
	}
	d := decodeYAML(t, buf.Bytes())
	statuses := map[string]int{}
	for _, r := range d.Results {
		statuses[r.Status]++
	}
	if statuses["pass"] != 0 || statuses["skipped"] != 0 {
		t.Errorf("--quiet should drop pass+skipped; got %+v", statuses)
	}
	if statuses["fail"] != 1 || statuses["error"] != 1 {
		t.Errorf("--quiet must keep fail+error rows; got %+v", statuses)
	}
	if d.Summary.Skipped != 1 {
		t.Errorf("summary counts must reflect full set; got %+v", d.Summary)
	}
}

// TestYAMLAndJSONAgreeOnFieldNames is a cross-format guard: the
// downstream contract is "same fields, same names, two encodings".
// Decoding YAML output and JSON output of the same input must produce
// equal Documents.
func TestYAMLAndJSONAgreeOnFieldNames(t *testing.T) {
	var jb, yb bytes.Buffer
	if err := JSON(&jb, sampleHeader(), sampleResults(), Options{}); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if err := YAML(&yb, sampleHeader(), sampleResults(), Options{}); err != nil {
		t.Fatalf("YAML: %v", err)
	}
	jd := decodeJSON(t, jb.Bytes())
	yd := decodeYAML(t, yb.Bytes())

	if jd.SchemaVersion != yd.SchemaVersion {
		t.Errorf("schema_version diverged: json=%d yaml=%d", jd.SchemaVersion, yd.SchemaVersion)
	}
	if jd.Summary != yd.Summary {
		t.Errorf("summary diverged:\n  json=%+v\n  yaml=%+v", jd.Summary, yd.Summary)
	}
	if len(jd.Results) != len(yd.Results) {
		t.Fatalf("results length diverged: json=%d yaml=%d", len(jd.Results), len(yd.Results))
	}
	for i := range jd.Results {
		if jd.Results[i].RuleID != yd.Results[i].RuleID || jd.Results[i].Status != yd.Results[i].Status {
			t.Errorf("result[%d] diverged:\n  json=%+v\n  yaml=%+v", i, jd.Results[i], yd.Results[i])
		}
	}
}
