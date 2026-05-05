package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"
)

// fetchSnapshots calls SnapshotInspector.Snapshots with an empty filter.
// The upstream resolves the empty Repository client-side by listing
// repos first and fanning out per repo, so the result is the union of
// snapshots across every registered repository.
//
// Result fields mirror snake_case json tags on types.Snapshot
// (snapshot, repository, state, indices, start_time_in_millis,
// end_time_in_millis, etc.).
func fetchSnapshots(ctx context.Context, si client.SnapshotInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snaps, err := si.Snapshots(ctx, types.SnapshotFilter{})
	if err != nil {
		return nil, fmt.Errorf("snapshots probe: %w", err)
	}
	return jsonShape("snapshots", snaps)
}

// fetchSnapshotRepositories calls SnapshotInspector.Repositories with
// an empty filter — every registered repository, regardless of type.
// JSON shape mirrors types.SnapshotRepository (name, type, settings).
func fetchSnapshotRepositories(ctx context.Context, si client.SnapshotInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	repos, err := si.Repositories(ctx, types.SnapshotRepositoryFilter{})
	if err != nil {
		return nil, fmt.Errorf("snapshot_repositories probe: %w", err)
	}
	return jsonShape("snapshot_repositories", repos)
}
