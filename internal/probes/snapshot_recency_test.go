package probes

import (
	"context"
	"testing"
	"time"

	"github.com/esops-dev/esops-go/pkg/types"
)

// TestSnapshotRecencyAggregatesPerRepository covers the headline
// aggregation: counts split by state, the most recent state, the
// latest-success age, and max-success-gap calculation that catches
// "schedule has been silently failing for a week" even when older
// successes exist.
func TestSnapshotRecencyAggregatesPerRepository(t *testing.T) {
	now := time.Now()
	hours := func(h float64) int64 {
		return now.Add(-time.Duration(h * float64(time.Hour))).UnixMilli()
	}

	si := &fakeSnapshotInspector{
		Repos: []types.SnapshotRepository{
			{Name: "prod"},
			{Name: "archive"},
		},
		Snaps: []types.Snapshot{
			// prod: three SUCCESS snapshots — 12h, 36h, and 240h ago —
			// plus one FAILED at 1h ago. Max gap should be 240→36h =
			// 204h (the gap between the oldest and middle SUCCESS).
			{Repository: "prod", Name: "p1", State: "SUCCESS", StartTimeMillis: hours(240)},
			{Repository: "prod", Name: "p2", State: "SUCCESS", StartTimeMillis: hours(36)},
			{Repository: "prod", Name: "p3", State: "SUCCESS", StartTimeMillis: hours(12)},
			{Repository: "prod", Name: "p4", State: "FAILED", StartTimeMillis: hours(1)},
			// archive: zero SUCCESS, two FAILED. untested_restore
			// territory: latest_success_age_hours absent.
			{Repository: "archive", Name: "a1", State: "FAILED", StartTimeMillis: hours(48)},
			{Repository: "archive", Name: "a2", State: "FAILED", StartTimeMillis: hours(24)},
		},
	}

	got, err := fetchSnapshotRecency(context.Background(), si)
	if err != nil {
		t.Fatalf("fetchSnapshotRecency: %v", err)
	}
	list, ok := got.([]any)
	if !ok {
		t.Fatalf("type = %T, want []any", got)
	}
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}

	byRepo := map[string]map[string]any{}
	for _, e := range list {
		m := e.(map[string]any)
		byRepo[m["repository"].(string)] = m
	}

	// prod: 4 snapshots total (3 SUCCESS, 1 FAILED), most recent
	// FAILED, latest SUCCESS ~12h ago, max gap ~204h.
	prod := byRepo["prod"]
	if prod == nil {
		t.Fatal("missing prod entry")
	}
	if int(prod["snapshot_count"].(float64)) != 4 {
		t.Errorf("prod snapshot_count = %v, want 4", prod["snapshot_count"])
	}
	if int(prod["success_count"].(float64)) != 3 {
		t.Errorf("prod success_count = %v, want 3", prod["success_count"])
	}
	if int(prod["failed_count"].(float64)) != 1 {
		t.Errorf("prod failed_count = %v, want 1", prod["failed_count"])
	}
	if prod["most_recent_state"] != "FAILED" {
		t.Errorf("prod most_recent_state = %v, want FAILED", prod["most_recent_state"])
	}
	if age := prod["latest_success_age_hours"].(float64); age < 11.5 || age > 12.5 {
		t.Errorf("prod latest_success_age_hours = %v, want ~12", age)
	}
	if gap := prod["max_success_gap_hours"].(float64); gap < 203.5 || gap > 204.5 {
		t.Errorf("prod max_success_gap_hours = %v, want ~204", gap)
	}

	// archive: 2 snapshots, both FAILED — no latest-success or gap
	// fields should be present (untested_restore relies on this).
	arc := byRepo["archive"]
	if arc == nil {
		t.Fatal("missing archive entry")
	}
	if int(arc["success_count"].(float64)) != 0 {
		t.Errorf("archive success_count = %v, want 0", arc["success_count"])
	}
	if _, present := arc["latest_success_age_hours"]; present {
		t.Error("archive latest_success_age_hours should be absent (no successes)")
	}
	if _, present := arc["max_success_gap_hours"]; present {
		t.Error("archive max_success_gap_hours should be absent (no successes)")
	}
}

// TestSnapshotRecencyMaxGapPicksUpOngoingSilence covers the case the
// motivating user story names: a single old SUCCESS plus a stretch of
// silence. Without the now→latest gap the rule would miss this; the
// test pins the behaviour so a future refactor can't quietly drop
// it.
func TestSnapshotRecencyMaxGapPicksUpOngoingSilence(t *testing.T) {
	now := time.Now()
	si := &fakeSnapshotInspector{
		Repos: []types.SnapshotRepository{{Name: "stale"}},
		Snaps: []types.Snapshot{
			// One SUCCESS, 10 days old. Nothing since.
			{
				Repository:      "stale",
				Name:            "s1",
				State:           "SUCCESS",
				StartTimeMillis: now.Add(-240 * time.Hour).UnixMilli(),
			},
		},
	}

	got, err := fetchSnapshotRecency(context.Background(), si)
	if err != nil {
		t.Fatalf("fetchSnapshotRecency: %v", err)
	}
	list := got.([]any)
	m := list[0].(map[string]any)
	gap := m["max_success_gap_hours"].(float64)
	if gap < 239.5 || gap > 240.5 {
		t.Errorf("max_success_gap_hours = %v, want ~240 (now − latest SUCCESS)", gap)
	}
}

// TestSnapshotRecencyEmptyRepoWithoutSnapshots covers the
// empty-but-registered repository case: untested_restore expects a
// row with snapshot_count=0 so it can skip the repo (the
// snapshot_repository_configured rule already covers "no repo
// registered" — overlapping the two would double-flag).
func TestSnapshotRecencyEmptyRepoWithoutSnapshots(t *testing.T) {
	si := &fakeSnapshotInspector{
		Repos: []types.SnapshotRepository{{Name: "fresh"}},
		Snaps: nil,
	}
	got, err := fetchSnapshotRecency(context.Background(), si)
	if err != nil {
		t.Fatalf("fetchSnapshotRecency: %v", err)
	}
	list := got.([]any)
	if len(list) != 1 {
		t.Fatalf("len = %d, want 1", len(list))
	}
	m := list[0].(map[string]any)
	if m["repository"] != "fresh" {
		t.Errorf("repository = %v, want fresh", m["repository"])
	}
	if int(m["snapshot_count"].(float64)) != 0 {
		t.Errorf("snapshot_count = %v, want 0", m["snapshot_count"])
	}
}

// TestSnapshotRecencyDeterministicOrder asserts the per-repo output
// is alphabetically sorted regardless of input order, so reports
// (json/yaml) and tests don't depend on the cluster's listing order.
func TestSnapshotRecencyDeterministicOrder(t *testing.T) {
	si := &fakeSnapshotInspector{
		Repos: []types.SnapshotRepository{
			{Name: "zulu"},
			{Name: "alpha"},
			{Name: "mike"},
		},
	}
	got, err := fetchSnapshotRecency(context.Background(), si)
	if err != nil {
		t.Fatalf("fetchSnapshotRecency: %v", err)
	}
	list := got.([]any)
	want := []string{"alpha", "mike", "zulu"}
	for i, e := range list {
		repo := e.(map[string]any)["repository"]
		if repo != want[i] {
			t.Errorf("list[%d] repository = %v, want %v", i, repo, want[i])
		}
	}
}
