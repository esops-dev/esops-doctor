package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
)

// fetchClusterSettingsFull calls ClusterSettingsFullInspector.GetClusterSettingsFull
// with includeDefaults=false. The default tree from /_cluster/settings
// is large (tens of KB) and the rules backed by this probe care about
// what the operator has set, not the cluster's built-in defaults.
//
// Adapter forces flat_settings=true so the returned maps are keyed by
// dotted-path names ("cluster.routing.allocation.awareness.attributes")
// rather than nested objects — rule conditions can reach for the key
// directly without walking persistent.cluster.routing.allocation.… in
// CEL.
//
// Result shape mirrors types.ClusterSettingsFull: { persistent: map,
// transient: map, defaults: map (empty here) }.
func fetchClusterSettingsFull(ctx context.Context, csi client.ClusterSettingsFullInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	view, err := csi.GetClusterSettingsFull(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("cluster_settings_full probe: %w", err)
	}
	return jsonShape("cluster_settings_full", view)
}
