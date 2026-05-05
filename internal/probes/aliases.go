package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"
)

// fetchAliases calls AliasInspector.Aliases with an empty filter — every
// alias→index binding the cluster has, regardless of dialect. JSON shape
// mirrors snake_case tags on types.Alias (alias, index, filter,
// is_write_index, etc.).
func fetchAliases(ctx context.Context, ai client.AliasInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	aliases, err := ai.Aliases(ctx, types.AliasFilter{})
	if err != nil {
		return nil, fmt.Errorf("aliases probe: %w", err)
	}
	return jsonShape("aliases", aliases)
}
