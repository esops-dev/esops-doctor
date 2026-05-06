package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
)

// fetchNodeBootstrap calls NodeBootstrapInspector.NodeBootstrap, the
// per-node bootstrap-check posture (mlockall, max_file_descriptors,
// max_map_count, plus the cluster's own bootstrap warning strings).
//
// Used by doctor's bootstrap_memory_lock and bootstrap-check parity
// rules. JSON shape mirrors types.NodeBootstrap snake_case tags:
// name, mlockall_enabled, max_file_descriptors, max_map_count,
// bootstrap_warnings.
func fetchNodeBootstrap(ctx context.Context, nbi client.NodeBootstrapInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := nbi.NodeBootstrap(ctx)
	if err != nil {
		return nil, fmt.Errorf("node_bootstrap probe: %w", err)
	}
	return jsonShape("node_bootstrap", rows)
}
