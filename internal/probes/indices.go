package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"
)

// fetchIndices calls IndexInspector.Indices with an empty filter — the
// /_cat/indices view across every non-hidden index, expanded to include
// hidden ones so rules can match on names like .ds-* and .watcher-*.
// JSON shape mirrors the snake_case tags on types.Index (status, health,
// docs_count, store_size_bytes, primaries, replicas, etc.).
func fetchIndices(ctx context.Context, ii client.IndexInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	indices, err := ii.Indices(ctx, types.IndexFilter{Hidden: true})
	if err != nil {
		return nil, fmt.Errorf("indices probe: %w", err)
	}
	return jsonShape("indices", indices)
}
