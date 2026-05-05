package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
)

// fetchNodeStats calls NodeStatsInspector.NodeStats (configured heap +
// OS memory, the /_nodes/jvm,os view). Used by the heap_size rule to
// check init/RAM ratios that /_cat/nodes can't report.
func fetchNodeStats(ctx context.Context, ni client.NodeStatsInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stats, err := ni.NodeStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("node_stats probe: %w", err)
	}
	return jsonShape("node_stats", stats)
}
