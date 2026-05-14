package cli

import (
	"encoding/json"
	"sort"
	"testing"
)

// TestEmbeddedSchemasShipExpectedNames asserts the binary ships the
// rule / profile / waiver schemas under their documented names. The
// embedded list is the contract operators rely on for `docs schemas
// --output-dir PATH`; a rename would silently break a YAML language
// server pointing at a fixed filename, so the catalog-hygiene gate
// belongs in code.
func TestEmbeddedSchemasShipExpectedNames(t *testing.T) {
	got, err := listSchemaEntries()
	if err != nil {
		t.Fatalf("listSchemaEntries: %v", err)
	}
	names := make([]string, 0, len(got))
	for _, e := range got {
		names = append(names, e.name)
	}
	sort.Strings(names)
	want := []string{"profile.schema.json", "rule.schema.json", "waiver.schema.json"}
	if len(names) != len(want) {
		t.Fatalf("embedded schemas = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("embedded[%d] = %q, want %q", i, names[i], want[i])
		}
	}
}

// TestEmbeddedSchemasParseAsJSON catches a malformed schema before it
// ships to operators. The bare JSON parse is intentionally lenient —
// we're not running a JSON-Schema metaschema validator (that would
// pull in a new dependency) — but a syntax error or missing $schema
// field would be a regression worth surfacing in CI.
func TestEmbeddedSchemasParseAsJSON(t *testing.T) {
	got, err := listSchemaEntries()
	if err != nil {
		t.Fatalf("listSchemaEntries: %v", err)
	}
	for _, e := range got {
		var doc map[string]any
		if err := json.Unmarshal(e.data, &doc); err != nil {
			t.Errorf("%s does not parse as JSON: %v", e.name, err)
			continue
		}
		if _, ok := doc["$schema"]; !ok {
			t.Errorf("%s is missing $schema", e.name)
		}
		if _, ok := doc["$id"]; !ok {
			t.Errorf("%s is missing $id", e.name)
		}
		if _, ok := doc["type"]; !ok {
			t.Errorf("%s is missing type", e.name)
		}
	}
}
