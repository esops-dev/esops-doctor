package probes

import (
	"context"
	"errors"
	"testing"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"

	"github.com/esops-dev/esops-doctor/internal/engine"
)

// One fake per capability. Each records call count for the
// "ErrUnsupported translation" test, which calls every adapter once
// against a fake that returns ErrUnsupported and asserts the registry
// translates it to engine.ErrProbeNotApplicable.

type fakeHealth struct{ Result types.ClusterHealth }

func (f *fakeHealth) Health(context.Context) (types.ClusterHealth, error) {
	return f.Result, nil
}

type fakeIndexInspector struct{ Result []types.Index }

func (f *fakeIndexInspector) Indices(context.Context, types.IndexFilter) ([]types.Index, error) {
	return f.Result, nil
}
func (f *fakeIndexInspector) IndicesNamesStatus(context.Context, types.IndexFilter) ([]types.IndexNameStatus, error) {
	return nil, nil
}
func (f *fakeIndexInspector) IndicesStream(context.Context, types.IndexFilter, func(types.Index) error) error {
	return nil
}

type fakeIndexSettingsInspector struct{ Result []types.IndexSettings }

func (f *fakeIndexSettingsInspector) GetSettings(context.Context, types.IndexSettingsGetRequest) ([]types.IndexSettings, error) {
	return f.Result, nil
}
func (f *fakeIndexSettingsInspector) GetSettingsStream(context.Context, types.IndexSettingsGetRequest, func(types.IndexSettings) error) error {
	return nil
}

type fakeIndexTemplateInspector struct{ Result []types.IndexTemplate }

func (f *fakeIndexTemplateInspector) GetTemplates(context.Context, []string) ([]types.IndexTemplate, error) {
	return f.Result, nil
}
func (f *fakeIndexTemplateInspector) GetTemplate(context.Context, string) (types.IndexTemplate, error) {
	return types.IndexTemplate{}, nil
}

type fakeAliasInspector struct{ Result []types.Alias }

func (f *fakeAliasInspector) Aliases(context.Context, types.AliasFilter) ([]types.Alias, error) {
	return f.Result, nil
}
func (f *fakeAliasInspector) AliasesStream(context.Context, types.AliasFilter, func(types.Alias) error) error {
	return nil
}

type fakeSnapshotInspector struct {
	Snaps []types.Snapshot
	Repos []types.SnapshotRepository
}

func (f *fakeSnapshotInspector) Snapshots(context.Context, types.SnapshotFilter) ([]types.Snapshot, error) {
	return f.Snaps, nil
}
func (f *fakeSnapshotInspector) Repositories(context.Context, types.SnapshotRepositoryFilter) ([]types.SnapshotRepository, error) {
	return f.Repos, nil
}
func (f *fakeSnapshotInspector) SnapshotStatus(context.Context, types.SnapshotStatusRequest) (types.SnapshotStatus, error) {
	return types.SnapshotStatus{}, nil
}
func (f *fakeSnapshotInspector) SnapshotsStream(context.Context, types.SnapshotFilter, func(types.Snapshot) error, func(string, error)) error {
	return nil
}

type fakeSecurityAuditor struct{ Result types.SecurityReport }

func (f *fakeSecurityAuditor) Audit(context.Context) (types.SecurityReport, error) {
	return f.Result, nil
}

type fakeRecoveryInspector struct{ Result types.RecoveryReport }

func (f *fakeRecoveryInspector) Recovery(context.Context, types.RecoveryRequest) (types.RecoveryReport, error) {
	return f.Result, nil
}

type fakeSegmentsInspector struct{ Result types.SegmentsReport }

func (f *fakeSegmentsInspector) Segments(context.Context, types.SegmentsRequest) (types.SegmentsReport, error) {
	return f.Result, nil
}

type fakeClusterSettingsInspector struct{ Result types.ClusterSettingsView }

func (f *fakeClusterSettingsInspector) GetClusterSettings(context.Context) (types.ClusterSettingsView, error) {
	return f.Result, nil
}

type fakePendingTasksInspector struct{ Result []types.PendingTask }

func (f *fakePendingTasksInspector) PendingTasks(context.Context) ([]types.PendingTask, error) {
	return f.Result, nil
}

// fakeDeprecationInspector defaults to ErrUnsupported (the OS-on-ES-only
// case). Tests that want a populated result on ES override Result and
// clear Err.
type fakeDeprecationInspector struct {
	Result []types.DeprecationIssue
	Err    error
}

func (f *fakeDeprecationInspector) Deprecations(context.Context, types.DeprecationsRequest) ([]types.DeprecationIssue, error) {
	return f.Result, f.Err
}

// ILM and ISM fakes return ErrUnsupported by default — the realistic
// "ILM on OpenSearch" and "ISM on Elasticsearch" cross-dialect cases.
// Tests that want a populated result override Result.
type fakeILM struct {
	Result []types.ILMPolicy
	Err    error
}

func (f *fakeILM) ListPolicies(context.Context, []string) ([]types.ILMPolicy, error) {
	return f.Result, f.Err
}
func (f *fakeILM) GetPolicy(context.Context, string) (types.ILMPolicy, error) {
	return types.ILMPolicy{}, f.Err
}
func (f *fakeILM) PutPolicy(context.Context, types.ILMPolicyPutRequest) (types.ILMPolicyPutResult, error) {
	return types.ILMPolicyPutResult{}, f.Err
}
func (f *fakeILM) DeletePolicy(context.Context, types.ILMPolicyDeleteRequest) (types.ILMPolicyDeleteResult, error) {
	return types.ILMPolicyDeleteResult{}, f.Err
}
func (f *fakeILM) ExplainPolicy(context.Context, types.ILMExplainRequest) ([]types.ILMExplainEntry, error) {
	return nil, f.Err
}
func (f *fakeILM) ExplainPolicyStream(context.Context, types.ILMExplainRequest, func(types.ILMExplainEntry) error) error {
	return f.Err
}

type fakeISM struct {
	Result []types.ISMPolicy
	Err    error
}

func (f *fakeISM) ListPolicies(context.Context, []string) ([]types.ISMPolicy, error) {
	return f.Result, f.Err
}
func (f *fakeISM) GetPolicy(context.Context, string) (types.ISMPolicy, error) {
	return types.ISMPolicy{}, f.Err
}
func (f *fakeISM) PutPolicy(context.Context, types.ISMPolicyPutRequest) (types.ISMPolicyPutResult, error) {
	return types.ISMPolicyPutResult{}, f.Err
}
func (f *fakeISM) DeletePolicy(context.Context, types.ISMPolicyDeleteRequest) (types.ISMPolicyDeleteResult, error) {
	return types.ISMPolicyDeleteResult{}, f.Err
}
func (f *fakeISM) ExplainPolicy(context.Context, types.ISMExplainRequest) ([]types.ISMExplainEntry, error) {
	return nil, f.Err
}
func (f *fakeISM) ExplainPolicyStream(context.Context, types.ISMExplainRequest, func(types.ISMExplainEntry) error) error {
	return f.Err
}

type fakeNodeBootstrapInspector struct{ Result []types.NodeBootstrap }

func (f *fakeNodeBootstrapInspector) NodeBootstrap(context.Context) ([]types.NodeBootstrap, error) {
	return f.Result, nil
}

type fakeNodeSettingsInspector struct{ Result []types.NodeSettings }

func (f *fakeNodeSettingsInspector) NodeSettings(context.Context) ([]types.NodeSettings, error) {
	return f.Result, nil
}

type fakeClusterSettingsFullInspector struct{ Result types.ClusterSettingsFull }

func (f *fakeClusterSettingsFullInspector) GetClusterSettingsFull(context.Context, bool) (types.ClusterSettingsFull, error) {
	return f.Result, nil
}

type fakeAllocationInspector struct{ Result []types.NodeAllocation }

func (f *fakeAllocationInspector) AllocationByNode(context.Context) ([]types.NodeAllocation, error) {
	return f.Result, nil
}

type fakeTransportTLSInspector struct{ Result types.TransportTLS }

func (f *fakeTransportTLSInspector) TransportTLS(context.Context) (types.TransportTLS, error) {
	return f.Result, nil
}

type fakeMappingsInspector struct{ Result []types.IndexMapping }

func (f *fakeMappingsInspector) GetMappings(context.Context, types.MappingFilter) ([]types.IndexMapping, error) {
	return f.Result, nil
}

type fakeHTTPTLSInspector struct{ Result types.HTTPTLSPosture }

func (f *fakeHTTPTLSInspector) HTTPTLS(context.Context) (types.HTTPTLSPosture, error) {
	return f.Result, nil
}

// fakeAuditLogInspector defaults to ErrUnsupported so the OS-without-
// audit-plugin and ES-without-audit-licence cases are the realistic
// shape an empty fake takes. Tests that want a populated result
// override Config / Warnings and clear Err.
type fakeAuditLogInspector struct {
	Config   types.AuditConfig
	Warnings []types.AuditWarning
	Err      error
}

func (f *fakeAuditLogInspector) AuditConfig(context.Context) (types.AuditConfig, error) {
	return f.Config, f.Err
}
func (f *fakeAuditLogInspector) AuditWarnings(context.Context, types.AuditWarningsRequest) ([]types.AuditWarning, error) {
	return f.Warnings, f.Err
}

type fakeRealmsInspector struct{ Result []types.Realm }

func (f *fakeRealmsInspector) Realms(context.Context) ([]types.Realm, error) {
	return f.Result, nil
}

// fakeAPIKeyInspector and fakeServiceTokenInspector default to no
// error so the dispatch sweep produces non-nil JSON shapes. The
// ErrUnsupported case is the OS-side reality and gets its own test
// arm in TestRegistryTranslatesUnsupported.
type fakeAPIKeyInspector struct {
	Result []types.APIKey
	Err    error
}

func (f *fakeAPIKeyInspector) APIKeys(context.Context) ([]types.APIKey, error) {
	return f.Result, f.Err
}

type fakeServiceTokenInspector struct {
	Result []types.ServiceToken
	Err    error
}

func (f *fakeServiceTokenInspector) ServiceTokens(context.Context) ([]types.ServiceToken, error) {
	return f.Result, f.Err
}

// fakeRemoteClusterInspector covers the three RemoteClusterInspector
// methods at once. RemoteClusters is shared across ES and OS so the
// default zero-value (empty slice, no error) is the realistic
// "nothing configured" shape. FollowerStats / AutoFollowPatterns are
// CCR-only — set Err to client.ErrUnsupported to exercise the
// dialect-skip path.
type fakeRemoteClusterInspector struct {
	Remotes     []types.RemoteCluster
	Followers   []types.FollowerStats
	AutoFollows []types.AutoFollowPattern
	Err         error
}

func (f *fakeRemoteClusterInspector) RemoteClusters(context.Context) ([]types.RemoteCluster, error) {
	return f.Remotes, f.Err
}
func (f *fakeRemoteClusterInspector) FollowerStats(context.Context) ([]types.FollowerStats, error) {
	return f.Followers, f.Err
}
func (f *fakeRemoteClusterInspector) AutoFollowPatterns(context.Context) ([]types.AutoFollowPattern, error) {
	return f.AutoFollows, f.Err
}

// fakeLicenseInspector returns a basic-licence-shaped LicenseStatus by
// default. ES-only at the upstream layer; tests covering the OS adapter
// override Err with client.ErrUnsupported.
type fakeLicenseInspector struct {
	Result types.LicenseStatus
	Err    error
}

func (f *fakeLicenseInspector) License(context.Context) (types.LicenseStatus, error) {
	return f.Result, f.Err
}

// fullClient assembles a *client.Client with every read-side capability
// the registry dispatches to, populated with the given fakes. Tests
// that exercise just one probe pass nils for the rest; tests that
// need cross-probe coverage populate every fake.
func fullClient() *client.Client {
	return &client.Client{
		Health:              &fakeHealth{},
		Nodes:               &fakeNodeInspector{},
		NodeStats:           &fakeNodeStatsInspector{},
		Indices:             &fakeIndexInspector{},
		IndexSettings:       &fakeIndexSettingsInspector{},
		IndexTemplateGet:    &fakeIndexTemplateInspector{},
		AliasInspect:        &fakeAliasInspector{},
		Snapshot:            &fakeSnapshotInspector{},
		ILM:                 &fakeILM{},
		ISM:                 &fakeISM{},
		Security:            &fakeSecurityAuditor{},
		Recovery:            &fakeRecoveryInspector{},
		Segments:            &fakeSegmentsInspector{},
		ClusterSettingsRead: &fakeClusterSettingsInspector{},
		PendingTasks:        &fakePendingTasksInspector{},
		Deprecations:        &fakeDeprecationInspector{},
		NodeBootstrap:       &fakeNodeBootstrapInspector{},
		NodeSettings:        &fakeNodeSettingsInspector{},
		ClusterSettingsAll:  &fakeClusterSettingsFullInspector{},
		Allocation:          &fakeAllocationInspector{},
		TransportTLS:        &fakeTransportTLSInspector{},
		Mappings:            &fakeMappingsInspector{},
		HTTPTLS:             &fakeHTTPTLSInspector{},
		AuditLog:            &fakeAuditLogInspector{},
		Realms:              &fakeRealmsInspector{},
		APIKeys:             &fakeAPIKeyInspector{},
		ServiceTokens:       &fakeServiceTokenInspector{},
		RemoteClusters:      &fakeRemoteClusterInspector{},
		License:             &fakeLicenseInspector{Result: types.LicenseStatus{Status: "active", Type: "basic"}},
	}
}

// TestRegistryDispatchesEveryProbe runs Probe(name) once for each name
// in Known() against a fully-populated *client.Client and asserts a
// non-nil result. Catches a missing dispatch arm (a probe that's in
// the Known set but has no switch case) — without this, validate-rules
// would accept a rule referencing the probe and the engine would
// silently report it as not-found.
func TestRegistryDispatchesEveryProbe(t *testing.T) {
	reg := New(fullClient())
	for _, name := range Known() {
		t.Run(name, func(t *testing.T) {
			got, err := reg.Probe(context.Background(), name)
			if err != nil {
				t.Fatalf("Probe(%q): %v", name, err)
			}
			if got == nil {
				t.Errorf("Probe(%q) returned nil; expected JSON-shaped data", name)
			}
		})
	}
}

// TestRegistryNilCapabilityPerProbe sweeps every probe name with a
// *client.Client whose corresponding capability is nil and asserts
// ErrProbeNotFound. Same defence as the dispatch sweep, but the other
// way: catches a switch arm that forgot the nil-guard.
func TestRegistryNilCapabilityPerProbe(t *testing.T) {
	for _, name := range Known() {
		t.Run(name, func(t *testing.T) {
			reg := New(&client.Client{}) // every capability nil
			_, err := reg.Probe(context.Background(), name)
			if !errors.Is(err, engine.ErrProbeNotFound) {
				t.Errorf("err should match ErrProbeNotFound; got %v", err)
			}
		})
	}
}

// TestRegistryTranslatesUnsupported asserts that probes calling a
// capability whose dialect-stub returns client.ErrUnsupported (the
// canonical case is ILM on OS / ISM on ES) surface as
// engine.ErrProbeNotApplicable so the engine reports Skipped with a
// dialect-specific reason rather than RuleStatusError.
func TestRegistryTranslatesUnsupported(t *testing.T) {
	cases := []struct {
		name  string
		probe string
	}{
		{"ilm on opensearch", ILMState},
		{"ism on elasticsearch", ISMState},
		{"deprecation_log on opensearch", DeprecationLog},
		{"api_keys on opensearch", APIKeys},
		{"service_tokens on opensearch", ServiceTokens},
		{"follower_stats on basic-licence cluster", FollowerStats},
		{"auto_follow_patterns on basic-licence cluster", AutoFollowPatterns},
		{"license on opensearch", License},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cl := &client.Client{
				ILM:            &fakeILM{Err: client.ErrUnsupported},
				ISM:            &fakeISM{Err: client.ErrUnsupported},
				Deprecations:   &fakeDeprecationInspector{Err: client.ErrUnsupported},
				APIKeys:        &fakeAPIKeyInspector{Err: client.ErrUnsupported},
				ServiceTokens:  &fakeServiceTokenInspector{Err: client.ErrUnsupported},
				RemoteClusters: &fakeRemoteClusterInspector{Err: client.ErrUnsupported},
				License:        &fakeLicenseInspector{Err: client.ErrUnsupported},
			}
			reg := New(cl)
			_, err := reg.Probe(context.Background(), c.probe)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, engine.ErrProbeNotApplicable) {
				t.Errorf("err should match ErrProbeNotApplicable; got %v", err)
			}
			if !errors.Is(err, client.ErrUnsupported) {
				t.Errorf("err should still wrap upstream ErrUnsupported; got %v", err)
			}
			if errors.Is(err, engine.ErrProbeNotFound) {
				t.Error("ErrUnsupported must NOT collapse to ErrProbeNotFound")
			}
		})
	}
}

// TestClusterHealthShape spot-checks the JSON-shape of one non-list
// probe (a single object) so a future refactor that breaks the
// json-round-trip path fails loudly. The other adapters are exercised
// by TestRegistryDispatchesEveryProbe for non-nil results; per-probe
// shape assertions for every probe would be a lot of mechanical test
// code without much marginal coverage.
func TestClusterHealthShape(t *testing.T) {
	cl := &client.Client{Health: &fakeHealth{Result: types.ClusterHealth{
		ClusterName:      "tests",
		Status:           "green",
		NumberOfNodes:    3,
		ActiveShards:     42,
		UnassignedShards: 0,
	}}}
	reg := New(cl)
	got, err := reg.Probe(context.Background(), ClusterHealth)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	m, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("type = %T, want map[string]any", got)
	}
	if m["cluster_name"] != "tests" {
		t.Errorf("cluster_name = %v, want \"tests\"", m["cluster_name"])
	}
	if m["status"] != "green" {
		t.Errorf("status = %v, want \"green\"", m["status"])
	}
}
