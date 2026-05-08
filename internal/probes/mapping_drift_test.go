package probes

import (
	"context"
	"testing"

	"github.com/esops-dev/esops-go/pkg/types"
)

// TestMappingDriftJoinsTemplatesAndIndices is the headline test for
// the cross-probe join: it sets up two templates with different
// index_patterns and asserts only the live index whose dynamic
// setting differs from its matching template surfaces.
func TestMappingDriftJoinsTemplatesAndIndices(t *testing.T) {
	mi := &fakeMappingsInspector{Result: []types.IndexMapping{
		// Drifted: template promises strict, live is true (cluster default
		// applied because the live index didn't pin it).
		{Name: "logs-2024-09", Dynamic: ""},
		// Aligned: template says false, live says false.
		{Name: "events-2024-09", Dynamic: "false"},
		// System index — should be dropped silently regardless of drift.
		{Name: ".internal-fleet", Dynamic: "true"},
		// No template matches: dropped silently.
		{Name: "scratch-index", Dynamic: "true"},
	}}
	it := &fakeIndexTemplateInspector{Result: []types.IndexTemplate{
		{
			Name:          "logs",
			IndexPatterns: []string{"logs-*"},
			Template: map[string]any{
				"mappings": map[string]any{"dynamic": "strict"},
			},
		},
		{
			Name:          "events",
			IndexPatterns: []string{"events-*"},
			Template: map[string]any{
				"mappings": map[string]any{"dynamic": "false"},
			},
		},
	}}

	got, err := fetchMappingDrift(context.Background(), mi, it)
	if err != nil {
		t.Fatalf("fetchMappingDrift: %v", err)
	}
	list, ok := got.([]any)
	if !ok {
		t.Fatalf("type = %T, want []any", got)
	}
	if len(list) != 1 {
		t.Fatalf("len = %d, want 1 (only logs-2024-09 should drift); got %v", len(list), list)
	}
	m := list[0].(map[string]any)
	if m["index"] != "logs-2024-09" {
		t.Errorf("index = %v, want logs-2024-09", m["index"])
	}
	if m["template"] != "logs" {
		t.Errorf("template = %v, want logs", m["template"])
	}
	if m["template_dynamic"] != "strict" {
		t.Errorf("template_dynamic = %v, want strict", m["template_dynamic"])
	}
	// The live mapping had dynamic="" — the probe materialises the
	// cluster default ("true") so the rule's comparison is between
	// two non-empty strings.
	if m["index_dynamic"] != "true" {
		t.Errorf("index_dynamic = %v, want true (cluster default materialised)", m["index_dynamic"])
	}
}

// TestMappingDriftMostSpecificPatternWins covers the priority rule:
// when two templates both match an index, the one with the longer
// (more specific) pattern owns the join. Catches a regression in
// matchTemplate that picks the first-hit instead of the longest.
func TestMappingDriftMostSpecificPatternWins(t *testing.T) {
	mi := &fakeMappingsInspector{Result: []types.IndexMapping{
		{Name: "logs-app-2024", Dynamic: "true"},
	}}
	it := &fakeIndexTemplateInspector{Result: []types.IndexTemplate{
		{
			// Catch-all template — promises strict, but should lose
			// to the more specific "logs-app-*".
			Name:          "all-logs",
			IndexPatterns: []string{"logs-*"},
			Template: map[string]any{
				"mappings": map[string]any{"dynamic": "strict"},
			},
		},
		{
			// Specific template — promises true, matches the live
			// dynamic, so no drift should be reported.
			Name:          "app-logs",
			IndexPatterns: []string{"logs-app-*"},
			Template: map[string]any{
				"mappings": map[string]any{"dynamic": "true"},
			},
		},
	}}

	got, err := fetchMappingDrift(context.Background(), mi, it)
	if err != nil {
		t.Fatalf("fetchMappingDrift: %v", err)
	}
	list := got.([]any)
	if len(list) != 0 {
		t.Errorf("len = %d, want 0 (more specific template aligns); got %v", len(list), list)
	}
}

// TestMappingDriftSkipsTemplatesWithoutDynamic asserts that templates
// that don't pin `dynamic` produce no drift entries — there's nothing
// to drift from. The cluster default applies and the rule has no
// opinion on it.
func TestMappingDriftSkipsTemplatesWithoutDynamic(t *testing.T) {
	mi := &fakeMappingsInspector{Result: []types.IndexMapping{
		{Name: "logs-2024-09", Dynamic: "true"},
	}}
	it := &fakeIndexTemplateInspector{Result: []types.IndexTemplate{
		{
			Name:          "logs",
			IndexPatterns: []string{"logs-*"},
			Template: map[string]any{
				"mappings": map[string]any{
					// No `dynamic` key.
					"properties": map[string]any{},
				},
			},
		},
	}}

	got, err := fetchMappingDrift(context.Background(), mi, it)
	if err != nil {
		t.Fatalf("fetchMappingDrift: %v", err)
	}
	list := got.([]any)
	if len(list) != 0 {
		t.Errorf("len = %d, want 0 (template did not pin dynamic)", len(list))
	}
}

// TestTemplateDynamicAcceptsBoolean covers an under-documented wire
// shape: ES/OS will accept `dynamic: true` as a boolean in a
// template, and at least some adapters round-trip it to bool rather
// than the string "true". The probe normalises both forms.
func TestTemplateDynamicAcceptsBoolean(t *testing.T) {
	for _, c := range []struct {
		name string
		in   any
		want string
	}{
		{"string strict", "strict", "strict"},
		{"bool true", true, "true"},
		{"bool false", false, "false"},
	} {
		t.Run(c.name, func(t *testing.T) {
			tpl := types.IndexTemplate{Template: map[string]any{
				"mappings": map[string]any{"dynamic": c.in},
			}}
			got := templateDynamic(tpl)
			if got != c.want {
				t.Errorf("templateDynamic = %q, want %q", got, c.want)
			}
		})
	}
}
