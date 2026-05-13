package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

// fakeHealthInspector returns canned health output for the probe
// command's smoke test. The probe command shells out to
// probes.Registry, which in turn invokes the upstream HealthInspector
// — this stub keeps the path testable without needing a live cluster.
type fakeHealthInspector struct{ Result types.ClusterHealth }

func (f *fakeHealthInspector) Health(context.Context) (types.ClusterHealth, error) {
	return f.Result, nil
}

// TestProbeNoArgListsKnownProbes confirms the no-arg form prints the
// registered probe set. Verifies the "discover what you can pass"
// surface a rule author reaches for first.
func TestProbeNoArgListsKnownProbes(t *testing.T) {
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{"esops-doctor", "probe"}); err != nil {
		t.Fatalf("probe: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"Registered probes:",
		"cluster_health",
		"node_stats",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in listing; got %q", want, out)
		}
	}
}

// TestProbeRejectsUnknownName confirms a typo in the probe name fails
// at exit 2 (usage), before any cluster work happens. Symmetrical to
// the typo'd --rule-id / --tags guards.
func TestProbeRejectsUnknownName(t *testing.T) {
	err := Run(context.Background(), []string{"esops-doctor", "probe", "totally_not_a_probe"})
	if err == nil {
		t.Fatal("expected usage error for unknown probe name")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("err should match ErrUsage; got %v", err)
	}
}

// TestProbePrintsClusterHealthShape drives the probe end-to-end with
// a stub HealthInspector and confirms the JSON output carries the
// probe name and a parseable data payload — what a rule author
// inspects when authoring a CEL condition.
func TestProbePrintsClusterHealthShape(t *testing.T) {
	stubConnect(t, &client.Client{
		Info: types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "t", Version: "9.0.0"},
		Health: &fakeHealthInspector{Result: types.ClusterHealth{
			ClusterName:       "test-cluster",
			Status:            "green",
			NumberOfNodes:     3,
			NumberOfDataNodes: 2,
		}},
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "probe", "--url", "http://example.invalid", "cluster_health",
	}); err != nil {
		t.Fatalf("probe: %v", err)
	}

	var doc struct {
		Probe string         `json:"probe"`
		Data  map[string]any `json:"data"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("not valid json: %v\n%s", err, stdout.String())
	}
	if doc.Probe != "cluster_health" {
		t.Errorf("probe = %q, want cluster_health", doc.Probe)
	}
	if doc.Data["cluster_name"] != "test-cluster" {
		t.Errorf("data.cluster_name = %v, want test-cluster", doc.Data["cluster_name"])
	}
	if doc.Data["status"] != "green" {
		t.Errorf("data.status = %v, want green", doc.Data["status"])
	}
}
