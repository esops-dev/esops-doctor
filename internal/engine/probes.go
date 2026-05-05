package engine

import (
	"context"
	"errors"
	"fmt"
)

// ProbeRegistry resolves probe names to the data the rule's CEL
// condition will see as `self`. Implementations are responsible for
// dialect awareness — the engine asks the registry for a probe name
// regardless of cluster dialect, and the registry returns dialect-
// appropriate data for the probed cluster.
//
// ErrProbeNotFound is the documented sentinel for "name not registered"
// so the engine can map it to a Skipped result; other errors are
// surfaced as evaluation failures (Status == RuleStatusError).
type ProbeRegistry interface {
	Probe(ctx context.Context, name string) (any, error)
}

// ErrProbeNotFound is returned by ProbeRegistry.Probe when the requested
// name has no registered adapter. The engine treats it as Skipped,
// distinct from genuine fetch errors (network timeouts, auth failures,
// etc.) which surface as RuleStatusError.
var ErrProbeNotFound = errors.New("probe not registered")

// ErrProbeNotApplicable signals "the probe is registered but the cluster
// doesn't expose this capability on its dialect" — the canonical case is
// ilm_state on OpenSearch (or ism_state on Elasticsearch). The engine
// treats it as Skipped with a different reason than ErrProbeNotFound, so
// an operator sees "ILM is Elasticsearch-only" rather than "probe not
// registered".
//
// Distinct sentinel rather than reusing ErrProbeNotFound because the
// causes are different — "registered but unavailable on this dialect"
// is a documented data point a rule author may want to express in CEL,
// while "not registered at all" is a catalog bug.
var ErrProbeNotApplicable = errors.New("probe not applicable to this cluster")

// MapRegistry is a fixed in-memory ProbeRegistry. Used in tests and as
// the v0.1 stand-in before the real probes/ adapters land. Returns
// ErrProbeNotFound for any name not in the map.
type MapRegistry map[string]any

// Probe satisfies ProbeRegistry. The context is accepted for interface
// conformance; an in-memory map has nothing to cancel.
func (m MapRegistry) Probe(_ context.Context, name string) (any, error) {
	data, ok := m[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrProbeNotFound, name)
	}
	return data, nil
}
