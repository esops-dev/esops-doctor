package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
)

// fetchNodeSettings calls NodeSettingsInspector.NodeSettings, the
// per-node static-settings view from /_nodes/settings?flat_settings=true.
// Sibling of NodeBootstrap (which only carries process / JVM blocks);
// this probe carries the whole `nodes.*.settings` map so rules can
// reach for any operator-set dotted-path key — network.host,
// node.store.allow_mmap, discovery.seed_hosts, etc. Cluster defaults
// are not merged in: keys the operator did not set are absent.
//
// JSON shape mirrors types.NodeSettings: { name, settings: {flat-key
// map} } per cluster node. Both ES and OS expose the same envelope,
// so the rule conditions are dialect-neutral by default.
func fetchNodeSettings(ctx context.Context, nsi client.NodeSettingsInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := nsi.NodeSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("node_settings probe: %w", err)
	}
	return jsonShape("node_settings", rows)
}
