package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
)

// fetchAllocation calls AllocationInspector.AllocationByNode — one row
// per node from /_cat/allocation, including the cluster's "UNASSIGNED"
// pseudo-node. Used by doctor's shard_count_per_node rule.
//
// JSON shape mirrors types.NodeAllocation snake_case tags: name,
// shards, disk_indices_bytes, disk_used_bytes, disk_avail_bytes,
// disk_total_bytes, disk_percent, host, ip.
func fetchAllocation(ctx context.Context, ai client.AllocationInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := ai.AllocationByNode(ctx)
	if err != nil {
		return nil, fmt.Errorf("allocation probe: %w", err)
	}
	return jsonShape("allocation", rows)
}
