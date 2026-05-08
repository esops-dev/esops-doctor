package probes

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"
)

// mappingFieldShape is one leaf field in a flattened mapping. Walking
// the nested types.IndexMapping.Properties tree client-side is
// dramatically simpler than asking each rule to do recursion in CEL —
// CEL comprehensions only iterate top-level lists. Rules over this
// probe filter the flat list with regular comprehensions.
//
// HasIgnoreAbove is a boolean rather than a presence-check on
// IgnoreAbove because CEL's `has(...)` semantics on JSON-roundtripped
// maps are subtle: a numeric zero for an unset field is
// indistinguishable from an explicit zero. The flag keeps the rule's
// condition unambiguous.
type mappingFieldShape struct {
	Index          string `json:"index"`
	Path           string `json:"path"`
	Type           string `json:"type"`
	HasIgnoreAbove bool   `json:"has_ignore_above"`
	IgnoreAbove    int    `json:"ignore_above,omitempty"`
	IsSystem       bool   `json:"is_system"`
}

// fetchMappingFields walks every index's mapping properties tree and
// emits one entry per leaf field carrying a `type`. Used by the
// deprecated_field_types and unbounded_keyword_cardinality rules,
// which both need a flat list to filter with CEL comprehensions.
//
// JSON shape: a slice of {index, path, type, has_ignore_above,
// ignore_above, is_system}. is_system is the dot-prefix marker the
// existing mapping rules use to opt system indices out of mapping
// hygiene checks (their schema is the cluster's call).
func fetchMappingFields(ctx context.Context, mi client.MappingsInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := mi.GetMappings(ctx, types.MappingFilter{
		Index:             "*",
		IgnoreUnavailable: true,
	})
	if err != nil {
		return nil, fmt.Errorf("mapping_fields probe: %w", err)
	}
	out := make([]mappingFieldShape, 0, len(rows)*8)
	for _, row := range rows {
		isSystem := strings.HasPrefix(row.Name, ".")
		walkMappingProperties(row.Name, "", row.Properties, isSystem, &out)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Index != out[j].Index {
			return out[i].Index < out[j].Index
		}
		return out[i].Path < out[j].Path
	})
	return jsonShape("mapping_fields", out)
}

// walkMappingProperties is the recursive worker. The mapping tree the
// cluster returns is map[string]any; each entry is either a leaf
// (carries `type`), an object (carries nested `properties`), or both
// (multi-fields under `fields`). The walker emits one row per leaf and
// recurses into nested properties / fields.
func walkMappingProperties(index, parent string, props map[string]any, isSystem bool, out *[]mappingFieldShape) {
	for name, raw := range props {
		field, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		path := name
		if parent != "" {
			path = parent + "." + name
		}
		if t, ok := field["type"].(string); ok && t != "" {
			entry := mappingFieldShape{
				Index:    index,
				Path:     path,
				Type:     t,
				IsSystem: isSystem,
			}
			if v, ok := field["ignore_above"]; ok {
				entry.HasIgnoreAbove = true
				switch n := v.(type) {
				case int:
					entry.IgnoreAbove = n
				case int64:
					entry.IgnoreAbove = int(n)
				case float64:
					entry.IgnoreAbove = int(n)
				}
			}
			*out = append(*out, entry)
		}
		if nested, ok := field["properties"].(map[string]any); ok {
			walkMappingProperties(index, path, nested, isSystem, out)
		}
		if subs, ok := field["fields"].(map[string]any); ok {
			walkMappingProperties(index, path, subs, isSystem, out)
		}
	}
}
