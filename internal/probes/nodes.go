package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
)

// fetchNodes calls NodeInspector.Nodes (one row per cluster node, the
// /_cat/nodes view) and returns the result as JSON-shaped data so rule
// conditions reference the same snake_case field names that appear in
// the upstream types.Node json tags (heap_max_bytes, disk_used_percent,
// roles, etc.).
func fetchNodes(ctx context.Context, ni client.NodeInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	nodes, err := ni.Nodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("nodes probe: %w", err)
	}
	return jsonShape("nodes", nodes)
}
