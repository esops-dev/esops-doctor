package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestPrintVersionJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := printVersion(&buf, "json"); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	for _, k := range []string{"name", "version", "commit", "date", "go_version", "esops_module", "cgo_enabled"} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
	if got["name"] != "esops-doctor" {
		t.Errorf("name = %v, want esops-doctor", got["name"])
	}
}

func TestPrintVersionText(t *testing.T) {
	var buf bytes.Buffer
	if err := printVersion(&buf, "text"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "esops-doctor") {
		t.Errorf("text output missing tool name: %q", out)
	}
	for _, want := range []string{"commit:", "built:", "go:", "esops-go:", "cgo:"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q: %q", want, out)
		}
	}
}

func TestPrintVersionUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := printVersion(&buf, "yaml"); err == nil {
		t.Error("expected error for unsupported format")
	}
}
