package probes

import (
	"context"
	"testing"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"
)

// TestSegmentsShape locks in the JSON keys the segments probe exposes
// to CEL. The rule conditions reference these names by string
// (`ix.max_segments_shard`, `ix.docs_deleted`, `ix.docs_total`,
// `ix.index`), so a rename of a field tag upstream would silently
// turn into vacuous passes under `has(...)` — exactly the failure mode
// the integration sweep can't catch because it only asserts non-nil
// data. This test pins each field rule code reads.
func TestSegmentsShape(t *testing.T) {
	fake := &fakeSegmentsInspector{Result: types.SegmentsReport{
		Indices: []types.IndexSegments{
			{
				Index:            "logs-2026-05",
				Shards:           3,
				SegmentsTotal:    90,
				SegmentsPrimary:  30,
				DocsTotal:        1_000_000,
				DocsDeleted:      400_000,
				Bytes:            10_485_760,
				MaxSegmentsShard: 73,
			},
		},
	}}
	reg := New(&client.Client{Segments: fake})

	got, err := reg.Probe(context.Background(), Segments)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	m, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("top-level type = %T, want map[string]any", got)
	}
	list, ok := m["indices"].([]any)
	if !ok {
		t.Fatalf("indices = %T, want []any", m["indices"])
	}
	if len(list) != 1 {
		t.Fatalf("indices length = %d, want 1", len(list))
	}
	ix, ok := list[0].(map[string]any)
	if !ok {
		t.Fatalf("indices[0] = %T, want map[string]any", list[0])
	}

	// String key the rule's startsWith('.') / startsWith('.ds-') checks
	// match against. Renames here silently break system-index exemption.
	if ix["index"] != "logs-2026-05" {
		t.Errorf("index = %v, want logs-2026-05", ix["index"])
	}

	// Numeric keys the rules read. JSON round-trip decodes int/int64
	// fields as float64; CEL needs the explicit int(...) conversion in
	// the rule (already in place). Missing any of these keys would let
	// `!has(ix.<key>)` short-circuit the rule to vacuous pass, so each
	// is asserted by name.
	for _, key := range []string{
		"max_segments_shard",
		"docs_total",
		"docs_deleted",
		"segments_total",
		"segments_primary",
		"bytes",
		"shards",
	} {
		v, present := ix[key]
		if !present {
			t.Errorf("indices[0].%s missing from probe shape", key)
			continue
		}
		if _, ok := v.(float64); !ok {
			t.Errorf("indices[0].%s = %T %v, want float64", key, v, v)
		}
	}
}

// TestSegmentsEmptyReport keeps the empty-cluster path honest: a fresh
// install with no indices must come back as `indices: []` (size 0), not
// nil. CEL's `self.indices.all(...)` over a null indices field would
// raise "no such overload" — the denilSlices walker in jsonShape
// prevents that, and this test guards against a regression.
func TestSegmentsEmptyReport(t *testing.T) {
	fake := &fakeSegmentsInspector{Result: types.SegmentsReport{Indices: nil}}
	reg := New(&client.Client{Segments: fake})

	got, err := reg.Probe(context.Background(), Segments)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	m, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("top-level type = %T, want map[string]any", got)
	}
	list, ok := m["indices"].([]any)
	if !ok {
		t.Fatalf("indices = %T %v, want []any (denilSlices should normalise nil)", m["indices"], m["indices"])
	}
	if len(list) != 0 {
		t.Errorf("indices length = %d, want 0", len(list))
	}
}
