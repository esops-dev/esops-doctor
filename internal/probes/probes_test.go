package probes

import (
	"context"
	"errors"
	"testing"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"

	"github.com/esops-dev/esops-doctor/internal/engine"
)

// fakeNodeInspector is the test double for client.NodeInspector.
type fakeNodeInspector struct {
	Result []types.Node
	Err    error
	Calls  int
}

func (f *fakeNodeInspector) Nodes(_ context.Context) ([]types.Node, error) {
	f.Calls++
	return f.Result, f.Err
}

// fakeNodeStatsInspector is the test double for client.NodeStatsInspector.
type fakeNodeStatsInspector struct {
	Result []types.NodeStats
	Err    error
	Calls  int
}

func (f *fakeNodeStatsInspector) NodeStats(_ context.Context) ([]types.NodeStats, error) {
	f.Calls++
	return f.Result, f.Err
}

func TestKnownProbesAreSorted(t *testing.T) {
	got := Known()
	for i := 1; i < len(got); i++ {
		if got[i] <= got[i-1] {
			t.Errorf("Known() not sorted at index %d: %q after %q (full: %v)",
				i, got[i], got[i-1], got)
			break
		}
	}
	// Spot-check a couple of probe names to catch a registration that
	// silently dropped them (the sort check above passes on an empty
	// slice). Adjust as the registered set grows.
	for _, name := range []string{Nodes, NodeStats, ClusterHealth, ClusterSettings, DeprecationLog, ILMState, ISMState, PendingTasks, Segments} {
		if !IsKnown(name) {
			t.Errorf("IsKnown(%q) = false, want true", name)
		}
	}
}

func TestIsKnownRejectsUnregistered(t *testing.T) {
	if IsKnown("definitely_not_a_probe") {
		t.Error("IsKnown should reject unregistered names")
	}
}

func TestRegistryDispatchesNodes(t *testing.T) {
	fake := &fakeNodeInspector{Result: []types.Node{
		{Name: "n1", IsDataNode: true, HeapMaxBytes: 8 * 1024 * 1024 * 1024},
	}}
	reg := New(&client.Client{Nodes: fake})

	got, err := reg.Probe(context.Background(), Nodes)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	list, ok := got.([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("Probe returned %T %v, want []any of length 1", got, got)
	}
	m, ok := list[0].(map[string]any)
	if !ok {
		t.Fatalf("element type = %T, want map[string]any", list[0])
	}
	if m["name"] != "n1" {
		t.Errorf("name = %v, want n1", m["name"])
	}
	// JSON round-trip yields float64 for numeric fields. Rules that
	// reference these fields use int(...) / double(...) conversions
	// where comparisons demand them.
	if _, ok := m["heap_max_bytes"].(float64); !ok {
		t.Errorf("heap_max_bytes = %T %v, want float64", m["heap_max_bytes"], m["heap_max_bytes"])
	}
	if fake.Calls != 1 {
		t.Errorf("upstream called %d time(s), want 1", fake.Calls)
	}
}

func TestRegistryDispatchesNodeStats(t *testing.T) {
	const gb = int64(1024 * 1024 * 1024)
	fake := &fakeNodeStatsInspector{Result: []types.NodeStats{
		{
			Name: "n1",
			JVM:  types.NodeJVMStats{Heap: types.NodeJVMHeap{InitBytes: 8 * gb, MaxBytes: 8 * gb}},
			OS:   types.NodeOSStats{TotalPhysicalMemoryBytes: 32 * gb},
		},
	}}
	reg := New(&client.Client{NodeStats: fake})

	got, err := reg.Probe(context.Background(), NodeStats)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	list, ok := got.([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("type/length = %T len=%d", got, len(list))
	}
	m, ok := list[0].(map[string]any)
	if !ok {
		t.Fatalf("element type = %T, want map[string]any", list[0])
	}
	jvm, ok := m["jvm"].(map[string]any)
	if !ok {
		t.Fatalf("jvm = %T %v, want map[string]any", m["jvm"], m["jvm"])
	}
	heap, ok := jvm["heap"].(map[string]any)
	if !ok {
		t.Fatalf("jvm.heap = %T", jvm["heap"])
	}
	if _, ok := heap["init_bytes"].(float64); !ok {
		t.Errorf("init_bytes = %T %v, want float64", heap["init_bytes"], heap["init_bytes"])
	}
	os, ok := m["os"].(map[string]any)
	if !ok {
		t.Fatalf("os = %T", m["os"])
	}
	if _, ok := os["total_physical_memory_bytes"].(float64); !ok {
		t.Errorf("total_physical_memory_bytes = %T", os["total_physical_memory_bytes"])
	}
}

func TestRegistryUnknownNameReturnsSentinel(t *testing.T) {
	reg := New(&client.Client{Nodes: &fakeNodeInspector{}})
	_, err := reg.Probe(context.Background(), "no_such_probe")
	if err == nil {
		t.Fatal("expected error for unregistered name")
	}
	if !errors.Is(err, engine.ErrProbeNotFound) {
		t.Errorf("err should match engine.ErrProbeNotFound; got %v", err)
	}
}

func TestRegistryNilCapabilityReturnsSentinel(t *testing.T) {
	// A capability not configured for this cluster (nil interface)
	// surfaces as ErrProbeNotFound so the engine reports Skipped, not
	// Error. Same shape as the "OpenSearch lacks ILM" case the upstream
	// adapters surface via unsupportedILM/unsupportedISM.
	reg := New(&client.Client{}) // every capability nil
	_, err := reg.Probe(context.Background(), Nodes)
	if !errors.Is(err, engine.ErrProbeNotFound) {
		t.Errorf("err should match engine.ErrProbeNotFound; got %v", err)
	}
	_, err = reg.Probe(context.Background(), NodeStats)
	if !errors.Is(err, engine.ErrProbeNotFound) {
		t.Errorf("err should match engine.ErrProbeNotFound; got %v", err)
	}
}

func TestRegistryNilClient(t *testing.T) {
	// Defensive: a nil *client.Client must not panic. The Registry
	// behaves as if every capability is unset (every probe Skipped).
	reg := New(nil)
	_, err := reg.Probe(context.Background(), Nodes)
	if !errors.Is(err, engine.ErrProbeNotFound) {
		t.Errorf("err should match engine.ErrProbeNotFound; got %v", err)
	}
}

func TestRegistrySurfacesUpstreamError(t *testing.T) {
	upstream := errors.New("cluster unreachable")
	reg := New(&client.Client{Nodes: &fakeNodeInspector{Err: upstream}})
	_, err := reg.Probe(context.Background(), Nodes)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, upstream) {
		t.Errorf("err should wrap upstream error; got %v", err)
	}
	if errors.Is(err, engine.ErrProbeNotFound) {
		t.Error("upstream fetch errors must NOT match ErrProbeNotFound")
	}
}

func TestRegistryHonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reg := New(&client.Client{Nodes: &fakeNodeInspector{}, NodeStats: &fakeNodeStatsInspector{}})
	if _, err := reg.Probe(ctx, Nodes); !errors.Is(err, context.Canceled) {
		t.Errorf("Nodes: expected context.Canceled, got %v", err)
	}
	if _, err := reg.Probe(ctx, NodeStats); !errors.Is(err, context.Canceled) {
		t.Errorf("NodeStats: expected context.Canceled, got %v", err)
	}
}

func TestFetchNodesEmptyClusterIsEmptySlice(t *testing.T) {
	// An empty cluster (e.g. a freshly-bootstrapped install) yields a
	// zero-length list, not nil. Rules with `size(self) > 0` guards
	// then fail explicitly rather than the CEL has() / null path.
	reg := New(&client.Client{Nodes: &fakeNodeInspector{Result: []types.Node{}}})
	got, err := reg.Probe(context.Background(), Nodes)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	list, ok := got.([]any)
	if !ok {
		t.Fatalf("type = %T, want []any", got)
	}
	if len(list) != 0 {
		t.Errorf("len = %d, want 0", len(list))
	}
}
