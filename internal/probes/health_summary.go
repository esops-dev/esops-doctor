package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
)

// HealthSummary is the subset of /_cluster/health that doctor surfaces
// in the report Header. Used by the cli to enrich a scan with cluster
// posture context (green/yellow/red, node and data-node counts) so a
// "1 rule passed" report carries useful flavour even on a clean scan.
type HealthSummary struct {
	Status            string
	NumberOfNodes     int
	NumberOfDataNodes int
}

// FetchHealthSummary calls the read-only HealthInspector once and
// returns the cluster posture fields the cli renders in the report
// header. Bypasses the engine probe cache because the cli runs this
// independently of rule evaluation; until parallel probe fetching
// lands, an engine rule that also uses cluster_health will fetch it
// twice — cheap (single GET) and acceptable as a stepping stone.
//
// Best-effort: a nil capability or transport failure returns an empty
// summary plus the underlying error; the cli treats either as "no
// posture data" and renders the report without those fields rather
// than failing the whole scan.
func FetchHealthSummary(ctx context.Context, cl *client.Client) (HealthSummary, error) {
	if cl == nil || cl.Health == nil {
		return HealthSummary{}, fmt.Errorf("cluster_health: HealthInspector capability not configured")
	}
	h, err := cl.Health.Health(ctx)
	if err != nil {
		return HealthSummary{}, fmt.Errorf("cluster_health: %w", err)
	}
	return HealthSummary{
		Status:            h.Status,
		NumberOfNodes:     h.NumberOfNodes,
		NumberOfDataNodes: h.NumberOfDataNodes,
	}, nil
}
