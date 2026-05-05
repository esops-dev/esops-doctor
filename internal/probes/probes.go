package probes

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/cluster"
	"github.com/esops-dev/esops-go/pkg/config"

	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/exit"
)

// Probe names registered with doctor. A rule's `probe:` field must
// match one of these; validate-rules consults Known() so a typo is
// caught at lint time rather than evaluation time.
const (
	Aliases              = "aliases"
	ClusterHealth        = "cluster_health"
	ClusterSettings      = "cluster_settings"
	DeprecationLog       = "deprecation_log"
	ILMState             = "ilm_state"
	ISMState             = "ism_state"
	Indices              = "indices"
	IndexSettings        = "index_settings"
	IndexTemplates       = "index_templates"
	NodeStats            = "node_stats"
	Nodes                = "nodes"
	PendingTasks         = "pending_tasks"
	Recovery             = "recovery"
	SecurityAudit        = "security_audit"
	SnapshotRepositories = "snapshot_repositories"
	Snapshots            = "snapshots"
)

// known is the registered probe-name set. Adding a probe means adding
// a constant above, an entry here, and a dispatch arm in Registry.Probe.
var known = map[string]struct{}{
	Aliases:              {},
	ClusterHealth:        {},
	ClusterSettings:      {},
	DeprecationLog:       {},
	ILMState:             {},
	ISMState:             {},
	Indices:              {},
	IndexSettings:        {},
	IndexTemplates:       {},
	NodeStats:            {},
	Nodes:                {},
	PendingTasks:         {},
	Recovery:             {},
	SecurityAudit:        {},
	SnapshotRepositories: {},
	Snapshots:            {},
}

// Known returns the registered probe names in deterministic order.
func Known() []string {
	out := make([]string, 0, len(known))
	for n := range known {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// IsKnown reports whether name is a registered probe.
func IsKnown(name string) bool {
	_, ok := known[name]
	return ok
}

// Connector is the function shape Connect satisfies. Exported so
// callers in other packages (cli/scan_test.go's stub) can declare a
// variable of this type without needing to import pkg/client
// themselves — the type alias hides the *client.Client return value
// behind the probes package boundary.
type Connector func(ctx context.Context, cc config.Context) (*client.Client, error)

// Connect resolves cc to a connected esops client by delegating to
// pkg/cluster.New. Lives in this package because probes is the single
// permitted importer of pkg/client (CLAUDE.md §5).
//
// Upstream sentinel errors (client.ErrUnreachable / ErrAuth /
// ErrForbidden / ErrUnknownProduct) are translated to the corresponding
// exit-package sentinels so the binary's exit code follows CLAUDE.md
// §10 without the exit package needing to import pkg/client.
func Connect(ctx context.Context, cc config.Context) (*client.Client, error) {
	cl, err := cluster.New(ctx, cc)
	if err != nil {
		return nil, translateClusterError(err)
	}
	return cl, nil
}

func translateClusterError(err error) error {
	switch {
	case errors.Is(err, client.ErrUnreachable):
		return fmt.Errorf("%w: %w", exit.ErrUnreachable, err)
	case errors.Is(err, client.ErrAuth):
		return fmt.Errorf("%w: %w", exit.ErrAuth, err)
	case errors.Is(err, client.ErrForbidden):
		return fmt.Errorf("%w: %w", exit.ErrForbidden, err)
	case errors.Is(err, client.ErrUnknownProduct):
		return fmt.Errorf("%w: %w", exit.ErrUnknownProduct, err)
	default:
		return fmt.Errorf("connecting to cluster: %w", err)
	}
}

// Registry adapts the read-only capability surface from esops-go/pkg/client
// to engine.ProbeRegistry. Each documented probe name dispatches to the
// adapter for its capability; capabilities not configured (nil interface)
// surface as engine.ErrProbeNotFound so the engine reports Skipped rather
// than Error.
type Registry struct {
	cl *client.Client
}

// New builds a Registry from a connected *client.Client. A nil cl is
// safe — every probe will report Skipped via ErrProbeNotFound. Tests
// that don't want a real cluster build a Client value with the fields
// they care about populated:
//
//	probes.New(&client.Client{Nodes: fakeNodes, Health: fakeHealth})
func New(cl *client.Client) *Registry {
	return &Registry{cl: cl}
}

// Probe satisfies engine.ProbeRegistry. The context is propagated to
// the upstream capability so cancellation kills an in-flight scan.
//
// Upstream's client.ErrUnsupported (the dialect-doesn't-have-this-feature
// case, e.g. ILM on OS) is translated to engine.ErrProbeNotApplicable so
// the engine reports Skipped with a clear reason rather than Error.
func (r *Registry) Probe(ctx context.Context, name string) (any, error) {
	data, err := r.dispatch(ctx, name)
	if err != nil && errors.Is(err, client.ErrUnsupported) {
		return nil, fmt.Errorf("%w: %w", engine.ErrProbeNotApplicable, err)
	}
	return data, err
}

// dispatch is the per-probe-name fan-out. Split from Probe so the
// ErrUnsupported translation wraps every adapter without duplication.
//
// Each arm checks the matching capability for nil before invoking the
// adapter — pkg/cluster.New wires every field on a real connect, but
// tests build partial *client.Client values and the registry must
// report a clean Skipped result rather than panic on nil method
// receivers.
func (r *Registry) dispatch(ctx context.Context, name string) (any, error) {
	cl := r.cl
	if cl == nil {
		return nil, notConfigured(name)
	}
	switch name {
	case Nodes:
		if cl.Nodes == nil {
			return nil, notConfigured(name)
		}
		return fetchNodes(ctx, cl.Nodes)
	case NodeStats:
		if cl.NodeStats == nil {
			return nil, notConfigured(name)
		}
		return fetchNodeStats(ctx, cl.NodeStats)
	case ClusterHealth:
		if cl.Health == nil {
			return nil, notConfigured(name)
		}
		return fetchClusterHealth(ctx, cl.Health)
	case Indices:
		if cl.Indices == nil {
			return nil, notConfigured(name)
		}
		return fetchIndices(ctx, cl.Indices)
	case IndexSettings:
		if cl.IndexSettings == nil {
			return nil, notConfigured(name)
		}
		return fetchIndexSettings(ctx, cl.IndexSettings)
	case IndexTemplates:
		if cl.IndexTemplateGet == nil {
			return nil, notConfigured(name)
		}
		return fetchIndexTemplates(ctx, cl.IndexTemplateGet)
	case Aliases:
		if cl.AliasInspect == nil {
			return nil, notConfigured(name)
		}
		return fetchAliases(ctx, cl.AliasInspect)
	case Snapshots:
		if cl.Snapshot == nil {
			return nil, notConfigured(name)
		}
		return fetchSnapshots(ctx, cl.Snapshot)
	case SnapshotRepositories:
		if cl.Snapshot == nil {
			return nil, notConfigured(name)
		}
		return fetchSnapshotRepositories(ctx, cl.Snapshot)
	case ILMState:
		if cl.ILM == nil {
			return nil, notConfigured(name)
		}
		return fetchILMState(ctx, cl.ILM)
	case ISMState:
		if cl.ISM == nil {
			return nil, notConfigured(name)
		}
		return fetchISMState(ctx, cl.ISM)
	case SecurityAudit:
		if cl.Security == nil {
			return nil, notConfigured(name)
		}
		return fetchSecurityAudit(ctx, cl.Security)
	case Recovery:
		if cl.Recovery == nil {
			return nil, notConfigured(name)
		}
		return fetchRecovery(ctx, cl.Recovery)
	case ClusterSettings:
		if cl.ClusterSettingsRead == nil {
			return nil, notConfigured(name)
		}
		return fetchClusterSettings(ctx, cl.ClusterSettingsRead)
	case PendingTasks:
		if cl.PendingTasks == nil {
			return nil, notConfigured(name)
		}
		return fetchPendingTasks(ctx, cl.PendingTasks)
	case DeprecationLog:
		if cl.Deprecations == nil {
			return nil, notConfigured(name)
		}
		return fetchDeprecations(ctx, cl.Deprecations)
	default:
		return nil, fmt.Errorf("%w: %s", engine.ErrProbeNotFound, name)
	}
}

func notConfigured(name string) error {
	return fmt.Errorf("%w: %s (capability not configured for this cluster)", engine.ErrProbeNotFound, name)
}
