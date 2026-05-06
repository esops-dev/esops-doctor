package probes

import (
	"reflect"
	"testing"
)

func TestJSONShapeNilTopLevelSliceBecomesEmpty(t *testing.T) {
	// Top-level untyped nil. CEL would reject `null` for a list-typed
	// `self`; we must surface `[]` instead.
	got, err := jsonShape("test", nil)
	if err != nil {
		t.Fatalf("jsonShape: %v", err)
	}
	list, ok := got.([]any)
	if !ok {
		t.Fatalf("type = %T, want []any", got)
	}
	if len(list) != 0 {
		t.Errorf("len = %d, want 0", len(list))
	}
}

func TestJSONShapeNilTypedSliceBecomesEmpty(t *testing.T) {
	// Typed nil slice ([]string(nil)). The walker has to check
	// rv.IsNil() on a Slice-kinded value, not a Pointer-kinded value.
	got, err := jsonShape("test", []string(nil))
	if err != nil {
		t.Fatalf("jsonShape: %v", err)
	}
	list, ok := got.([]any)
	if !ok || list == nil {
		t.Fatalf("type = %T, want non-nil []any", got)
	}
	if len(list) != 0 {
		t.Errorf("len = %d, want 0", len(list))
	}
}

// nestedFixture mimics the shape probe results carry: nested structs
// with slice fields and a slice-of-structs each with their own slice
// field. The motivating case is RecoveryReport.Indices being nil on a
// freshly-bootstrapped cluster — the json round-trip would marshal the
// nil to "null" and CEL would reject the `self.indices.all(...)`
// traversal.
type nestedFixture struct {
	Name    string             `json:"name"`
	Indices []nestedIndex      `json:"indices"`           // top-level field; non-nil after denil
	Tags    []string           `json:"tags,omitempty"`    // omitempty: nil here is fine, but denil leaves it as []
	Mapping map[string]nestedM `json:"mapping,omitempty"` // map-of-struct: walker has to handle non-addressable values
}

type nestedIndex struct {
	Index  string   `json:"index"`
	Shards []string `json:"shards"` // nested nil slice — the case we care about
}

type nestedM struct {
	Aliases []string `json:"aliases"`
}

func TestJSONShapeDeepDenilStructFields(t *testing.T) {
	in := nestedFixture{
		Name: "fresh",
		// Indices is nil on purpose (the cluster reported no indices).
		// Tags is nil too. Mapping has one entry whose nested slice is nil.
		Mapping: map[string]nestedM{"alias_a": {Aliases: nil}},
	}
	got, err := jsonShape("test", in)
	if err != nil {
		t.Fatalf("jsonShape: %v", err)
	}
	m, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("type = %T, want map[string]any", got)
	}

	if !reflect.DeepEqual(m["indices"], []any{}) {
		t.Errorf("indices = %#v, want empty []any", m["indices"])
	}
	// Tags is omitempty: marshal omits it when empty. CEL rule authors
	// use has() for omitempty fields, so an absent key is fine — the
	// guarantee is "no `null` value sneaks through", not "every field is
	// always present".
	if v, ok := m["tags"]; ok && !reflect.DeepEqual(v, []any{}) {
		t.Errorf("tags = %#v; expected omitted or []any", v)
	}

	mp, ok := m["mapping"].(map[string]any)
	if !ok {
		t.Fatalf("mapping type = %T", m["mapping"])
	}
	aliasA, ok := mp["alias_a"].(map[string]any)
	if !ok {
		t.Fatalf("mapping[alias_a] type = %T", mp["alias_a"])
	}
	if !reflect.DeepEqual(aliasA["aliases"], []any{}) {
		t.Errorf("mapping[alias_a].aliases = %#v, want empty []any", aliasA["aliases"])
	}
}

func TestJSONShapePreservesNonNilSlices(t *testing.T) {
	// Sanity check: denil must not stomp non-nil data.
	in := nestedFixture{
		Name:    "populated",
		Indices: []nestedIndex{{Index: "logs-1", Shards: []string{"0", "1"}}},
		Tags:    []string{"prod"},
	}
	got, err := jsonShape("test", in)
	if err != nil {
		t.Fatalf("jsonShape: %v", err)
	}
	m := got.(map[string]any)
	idxs := m["indices"].([]any)
	if len(idxs) != 1 {
		t.Fatalf("indices len = %d, want 1", len(idxs))
	}
	first := idxs[0].(map[string]any)
	if first["index"] != "logs-1" {
		t.Errorf("indices[0].index = %v, want logs-1", first["index"])
	}
	shards := first["shards"].([]any)
	if len(shards) != 2 {
		t.Errorf("shards len = %d, want 2", len(shards))
	}
}
