package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
)

// fetchILMState lists every ILM policy via ListPolicies(nil) — passing
// nil lets the cluster return every entry. ILM is Elasticsearch-only;
// the OpenSearch adapter returns client.ErrUnsupported on every method,
// which the registry translates to engine.ErrProbeNotApplicable so the
// rule is reported as Skipped with a dialect-specific reason.
func fetchILMState(ctx context.Context, ilm client.ILMManager) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	policies, err := ilm.ListPolicies(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("ilm_state probe: %w", err)
	}
	return jsonShape("ilm_state", policies)
}

// fetchISMState lists every ISM policy via ListPolicies(nil). ISM is
// OpenSearch-only; the Elasticsearch adapter returns
// client.ErrUnsupported, translated by the registry to
// engine.ErrProbeNotApplicable.
func fetchISMState(ctx context.Context, ism client.ISMManager) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	policies, err := ism.ListPolicies(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("ism_state probe: %w", err)
	}
	return jsonShape("ism_state", policies)
}
