package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
)

// fetchClusterHealth calls HealthInspector.Health and returns the
// /_cluster/health document as JSON-shaped data. Single object, not a
// list — rule conditions index fields directly:
//
//	self.status == "green"
//	int(self.unassigned_shards) == 0
func fetchClusterHealth(ctx context.Context, h client.HealthInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	health, err := h.Health(ctx)
	if err != nil {
		return nil, fmt.Errorf("cluster_health probe: %w", err)
	}
	return jsonShape("cluster_health", health)
}
