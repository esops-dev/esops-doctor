package probes

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"
)

// snapshotRecencyShape is one per-repository roll-up over the snapshot
// list. The fields are pre-aggregated in Go so CEL conditions stay
// trivial — neither dialect's query API exposes "most recent SUCCESS
// per repo" directly, so doing it client-side once per scan is cheaper
// (and clearer) than asking each rule to walk a flat list and
// recompute.
//
// Fields with `_age_hours` suffixes are populated only when the
// underlying snapshot's start_time_in_millis was non-zero — a missing
// timestamp on an upstream record means the cluster did not surface
// it, so any age would be a guess.
type snapshotRecencyShape struct {
	Repository string `json:"repository"`
	// Counts split by state so untested_restore can flag "snapshots
	// exist but none ever finished cleanly" without re-walking the
	// flat list.
	SnapshotCount int `json:"snapshot_count"`
	SuccessCount  int `json:"success_count"`
	FailedCount   int `json:"failed_count"`
	PartialCount  int `json:"partial_count"`
	InProgress    int `json:"in_progress_count"`
	// MostRecentState is the state of the chronologically newest
	// snapshot regardless of state — used to flag "the most recent
	// attempt was FAILED" even when older successes exist.
	MostRecentState string `json:"most_recent_state,omitempty"`
	// LatestSuccessAgeHours is hours since the most recent SUCCESS
	// snapshot. Absent when there is no SUCCESS snapshot or when none
	// of the SUCCESS snapshots carried a start time.
	LatestSuccessAgeHours *float64 `json:"latest_success_age_hours,omitempty"`
	// MaxSuccessGapHours is the largest gap (in hours) between
	// consecutive SUCCESS snapshots ordered by start time, plus the
	// gap between the most recent SUCCESS and "now". Catches "the
	// schedule has been silently failing for a week even though a
	// success exists from before the failures started". Absent when
	// there are fewer than two SUCCESS snapshots with timestamps.
	MaxSuccessGapHours *float64 `json:"max_success_gap_hours,omitempty"`
}

// fetchSnapshotRecency lists every snapshot and aggregates per-repo.
// Lives next to the snapshots probe (which surfaces the flat list)
// because the rules driven by recency want pre-computed gaps and ages
// the flat list cannot give them in CEL.
//
// The aggregation is "now"-relative; we capture time.Now() once at
// probe time so the rule's findings reflect a single instant rather
// than drifting between rule evaluations.
func fetchSnapshotRecency(ctx context.Context, si client.SnapshotInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snaps, err := si.Snapshots(ctx, types.SnapshotFilter{})
	if err != nil {
		return nil, fmt.Errorf("snapshot_recency probe: %w", err)
	}
	repos, err := si.Repositories(ctx, types.SnapshotRepositoryFilter{})
	if err != nil {
		return nil, fmt.Errorf("snapshot_recency probe: %w", err)
	}

	now := time.Now()
	byRepo := make(map[string]*snapshotRecencyShape, len(repos))
	for _, r := range repos {
		byRepo[r.Name] = &snapshotRecencyShape{Repository: r.Name}
	}
	// Snapshots whose Repository field names a repo we did not see in
	// the Repositories() result still get a roll-up — the cluster
	// reported them, the operator should see them.
	for _, s := range snaps {
		entry, ok := byRepo[s.Repository]
		if !ok {
			entry = &snapshotRecencyShape{Repository: s.Repository}
			byRepo[s.Repository] = entry
		}
		entry.SnapshotCount++
		switch s.State {
		case "SUCCESS":
			entry.SuccessCount++
		case "FAILED":
			entry.FailedCount++
		case "PARTIAL", "INCOMPATIBLE":
			entry.PartialCount++
		case "IN_PROGRESS", "STARTED":
			entry.InProgress++
		}
	}

	// Per-repo timeline reductions. Group by repo, then sort the
	// SUCCESS subset by start time so we can compute both the latest
	// age and the max gap in one pass.
	groups := make(map[string][]types.Snapshot, len(byRepo))
	for _, s := range snaps {
		groups[s.Repository] = append(groups[s.Repository], s)
	}
	for repo, list := range groups {
		entry := byRepo[repo]
		if entry == nil {
			continue
		}
		// Most-recent-state regardless of state: chronological max by
		// start time. A snapshot without a start time is dropped from
		// this comparison — its position in the timeline is unknown.
		var newest *types.Snapshot
		for i := range list {
			s := &list[i]
			if s.StartTimeMillis == 0 {
				continue
			}
			if newest == nil || s.StartTimeMillis > newest.StartTimeMillis {
				newest = s
			}
		}
		if newest != nil {
			entry.MostRecentState = newest.State
		}

		successes := make([]types.Snapshot, 0, len(list))
		for _, s := range list {
			if s.State == "SUCCESS" && s.StartTimeMillis != 0 {
				successes = append(successes, s)
			}
		}
		sort.Slice(successes, func(i, j int) bool {
			return successes[i].StartTimeMillis < successes[j].StartTimeMillis
		})
		if n := len(successes); n > 0 {
			latest := time.UnixMilli(successes[n-1].StartTimeMillis)
			ageH := now.Sub(latest).Hours()
			entry.LatestSuccessAgeHours = &ageH

			// Max gap considers the gap between the most recent
			// success and "now" so a long stretch of silence after a
			// success is itself a finding.
			maxGap := now.Sub(latest).Hours()
			for i := 1; i < n; i++ {
				prev := time.UnixMilli(successes[i-1].StartTimeMillis)
				cur := time.UnixMilli(successes[i].StartTimeMillis)
				gap := cur.Sub(prev).Hours()
				if gap > maxGap {
					maxGap = gap
				}
			}
			entry.MaxSuccessGapHours = &maxGap
		}
	}

	// Deterministic ordering — rules don't depend on it but reports
	// (json/yaml) and tests do.
	out := make([]snapshotRecencyShape, 0, len(byRepo))
	for _, e := range byRepo {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repository < out[j].Repository })
	return jsonShape("snapshot_recency", out)
}
