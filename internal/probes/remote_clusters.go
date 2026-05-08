package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
)

// fetchRemoteClusters calls RemoteClusterInspector.RemoteClusters
// (GET /_remote/info). Both ES and OS speak this endpoint; CCS-readiness
// rules consume the resulting list to flag remotes that are configured
// but not currently reachable.
//
// Returns a slice — empty when no remotes are configured (the
// cluster's own "everything OK, nothing to inspect" shape). The rule
// consumer treats size(self)==0 as a vacuous pass.
func fetchRemoteClusters(ctx context.Context, ri client.RemoteClusterInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := ri.RemoteClusters(ctx)
	if err != nil {
		return nil, fmt.Errorf("remote_clusters probe: %w", err)
	}
	return jsonShape("remote_clusters", rows)
}

// fetchFollowerStats calls RemoteClusterInspector.FollowerStats
// (GET /_ccr/stats). Elasticsearch-only at the upstream layer; the OS
// adapter returns ErrUnsupported, which the registry translates to
// engine.ErrProbeNotApplicable so the matching rule auto-skips with
// a stable reason. A basic-licence ES cluster also returns
// ErrUnsupported (404 → CCR not licensed) — same skip path.
func fetchFollowerStats(ctx context.Context, ri client.RemoteClusterInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := ri.FollowerStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("follower_stats probe: %w", err)
	}
	return jsonShape("follower_stats", rows)
}

// fetchAutoFollowPatterns calls RemoteClusterInspector.AutoFollowPatterns
// (GET /_ccr/auto_follow). Same dialect / licence story as
// fetchFollowerStats — ES-only and CCR-licensed-only at the cluster
// level, ErrUnsupported flows through to a Skipped rule result.
func fetchAutoFollowPatterns(ctx context.Context, ri client.RemoteClusterInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := ri.AutoFollowPatterns(ctx)
	if err != nil {
		return nil, fmt.Errorf("auto_follow_patterns probe: %w", err)
	}
	return jsonShape("auto_follow_patterns", rows)
}
