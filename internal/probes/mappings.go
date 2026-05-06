package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"
)

// fetchMappings calls MappingsInspector.GetMappings across every index
// (filter Index="*", IgnoreUnavailable=true so a fresh cluster with
// zero indices returns an empty slice rather than a 404). Used by
// doctor's mapping anti-pattern rules — dynamic_mapping_strict,
// deeply_nested_objects, etc.
//
// JSON shape mirrors types.IndexMapping: { name, properties (raw map),
// meta (raw map), dynamic (string) }. Properties is the cluster's
// nested mapping tree verbatim; rules walk it via CEL field access
// rather than expecting a flattened form.
func fetchMappings(ctx context.Context, mi client.MappingsInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := mi.GetMappings(ctx, types.MappingFilter{
		Index:             "*",
		IgnoreUnavailable: true,
	})
	if err != nil {
		return nil, fmt.Errorf("mappings probe: %w", err)
	}
	return jsonShape("mappings", rows)
}
