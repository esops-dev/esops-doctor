package probes

import (
	"context"
	"testing"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"
)

// TestMappingFieldsFlattensNestedAndMultiFields exercises the walker
// over a realistic mapping shape: top-level keyword, nested object,
// and a text field with a `fields:` multi-field. The walker has to
// yield one entry per leaf carrying a `type` and recurse into both
// `properties` and `fields` blocks.
func TestMappingFieldsFlattensNestedAndMultiFields(t *testing.T) {
	mi := &fakeMappingsInspector{Result: []types.IndexMapping{{
		Name: "logs-2024-09",
		Properties: map[string]any{
			"user": map[string]any{
				"properties": map[string]any{
					"id": map[string]any{"type": "keyword", "ignore_above": 1024},
					"name": map[string]any{
						"type": "text",
						"fields": map[string]any{
							"keyword": map[string]any{"type": "keyword"},
						},
					},
				},
			},
			"message": map[string]any{"type": "text"},
		},
	}}}

	got, err := fetchMappingFields(context.Background(), mi)
	if err != nil {
		t.Fatalf("fetchMappingFields: %v", err)
	}
	list, ok := got.([]any)
	if !ok {
		t.Fatalf("type = %T, want []any", got)
	}

	// Build a path → entry index for spot checks. The probe pre-sorts
	// by (index, path), but asserting by sorted position would couple
	// the test to the sort order; map lookup is clearer.
	byPath := make(map[string]map[string]any, len(list))
	for _, e := range list {
		m := e.(map[string]any)
		byPath[m["path"].(string)] = m
	}

	for _, c := range []struct {
		path          string
		wantType      string
		wantHasIgnore bool
		wantIgnoreVal int
	}{
		{"user.id", "keyword", true, 1024},
		{"user.name", "text", false, 0},
		{"user.name.keyword", "keyword", false, 0},
		{"message", "text", false, 0},
	} {
		t.Run(c.path, func(t *testing.T) {
			m, ok := byPath[c.path]
			if !ok {
				t.Fatalf("missing path %q in flattened output (have: %v)", c.path, paths(byPath))
			}
			if m["type"] != c.wantType {
				t.Errorf("type = %v, want %v", m["type"], c.wantType)
			}
			if m["has_ignore_above"] != c.wantHasIgnore {
				t.Errorf("has_ignore_above = %v, want %v", m["has_ignore_above"], c.wantHasIgnore)
			}
			if c.wantHasIgnore {
				if int(m["ignore_above"].(float64)) != c.wantIgnoreVal {
					t.Errorf("ignore_above = %v, want %d", m["ignore_above"], c.wantIgnoreVal)
				}
			}
		})
	}

	// The "user" object itself has no `type`, only nested properties —
	// it should not surface as a leaf.
	if _, leaked := byPath["user"]; leaked {
		t.Error(`"user" object surfaced as leaf field; only typed leaves should appear`)
	}
}

// TestMappingFieldsMarksSystemIndices ensures dot-prefixed indices are
// surfaced with is_system=true so rules can opt out by default — the
// existing mapping rules use this same convention.
func TestMappingFieldsMarksSystemIndices(t *testing.T) {
	mi := &fakeMappingsInspector{Result: []types.IndexMapping{
		{Name: ".internal-fleet", Properties: map[string]any{
			"version": map[string]any{"type": "keyword"},
		}},
		{Name: "user-events", Properties: map[string]any{
			"id": map[string]any{"type": "keyword"},
		}},
	}}

	got, err := fetchMappingFields(context.Background(), mi)
	if err != nil {
		t.Fatalf("fetchMappingFields: %v", err)
	}
	list := got.([]any)
	for _, e := range list {
		m := e.(map[string]any)
		isSystem := m["is_system"].(bool)
		want := m["index"].(string) == ".internal-fleet"
		if isSystem != want {
			t.Errorf("index %q: is_system = %v, want %v", m["index"], isSystem, want)
		}
	}
}

// TestMappingFieldsEmptyClusterIsEmptySlice mirrors the assertion the
// probes_test.go's TestFetchNodesEmptyClusterIsEmptySlice makes for
// the nodes probe — fresh-install clusters return an empty list, not
// nil. Without this, rules guarded by `size(self) == 0` would fail
// the CEL has()/null path on an empty cluster.
func TestMappingFieldsEmptyClusterIsEmptySlice(t *testing.T) {
	mi := &fakeMappingsInspector{Result: nil}
	got, err := fetchMappingFields(context.Background(), mi)
	if err != nil {
		t.Fatalf("fetchMappingFields: %v", err)
	}
	list, ok := got.([]any)
	if !ok {
		t.Fatalf("type = %T, want []any", got)
	}
	if len(list) != 0 {
		t.Errorf("len = %d, want 0", len(list))
	}
}

// errFakeMappingsInspector returns an upstream error on every call,
// used to assert the probe surfaces it verbatim (wrapped) rather than
// swallowing or translating.
type errFakeMappingsInspector struct{ Err error }

func (f *errFakeMappingsInspector) GetMappings(context.Context, types.MappingFilter) ([]types.IndexMapping, error) {
	return nil, f.Err
}

// Compile-time check the test fake satisfies the inspector contract.
var _ client.MappingsInspector = (*errFakeMappingsInspector)(nil)

func paths(byPath map[string]map[string]any) []string {
	out := make([]string, 0, len(byPath))
	for k := range byPath {
		out = append(out, k)
	}
	return out
}
