package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
)

// fetchClusterSettings calls ClusterSettingsInspector.GetClusterSettings.
// The capability is the read-only sibling of ClusterSettingsManager —
// distinct interface so doctor can depend on it without pulling in the
// "Put*" mutating methods on the manager (which sit on the forbidden
// symbols list).
//
// Result mirrors types.ClusterSettingsView (persistent / transient
// blocks of allocation-exclude name lists). Single object, not a list.
func fetchClusterSettings(ctx context.Context, csi client.ClusterSettingsInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	view, err := csi.GetClusterSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("cluster_settings probe: %w", err)
	}
	return jsonShape("cluster_settings", view)
}
