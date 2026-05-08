package probes

import (
	"context"
	"fmt"
	"time"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"
)

// serviceTokenShape mirrors types.ServiceToken and adds age_days.
// File-realm tokens carry a zero Creation upstream by design (the
// cluster does not timestamp them); age_days is omitted in that case
// so the stale_service_tokens rule cannot fire on a cluster with
// nothing but file-realm tokens. Source distinguishes mutable
// index-stored tokens from file-realm ones, which the rule uses to
// scope its check.
type serviceTokenShape struct {
	Name      string    `json:"name"`
	Namespace string    `json:"namespace"`
	Service   string    `json:"service"`
	Creation  time.Time `json:"creation,omitempty"`
	Source    string    `json:"source"`
	AgeDays   *float64  `json:"age_days,omitempty"`
}

// fetchServiceTokens calls ServiceTokenInspector.ServiceTokens — the
// ES-only view of credentials issued for service accounts (Fleet,
// APM Server, and similar). Used by doctor's stale_service_tokens
// rule.
//
// Result is a list of {name, namespace, service, creation, source,
// age_days} entries. The OS adapter is the unsupported stub, so this
// probe surfaces engine.ErrProbeNotApplicable on OS via the registry's
// ErrUnsupported translation and the rule reports Skipped.
func fetchServiceTokens(ctx context.Context, t client.ServiceTokenInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tokens, err := t.ServiceTokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("service_tokens probe: %w", err)
	}
	now := time.Now()
	out := make([]serviceTokenShape, 0, len(tokens))
	for _, tok := range tokens {
		entry := serviceTokenShape{
			Name:      tok.Name,
			Namespace: tok.Namespace,
			Service:   tok.Service,
			Creation:  tok.Creation,
			Source:    tok.Source,
		}
		if !tok.Creation.IsZero() {
			age := now.Sub(tok.Creation).Hours() / 24
			entry.AgeDays = &age
		}
		out = append(out, entry)
	}
	return jsonShape("service_tokens", out)
}

// Compile-time check that serviceTokenShape covers every field of
// types.ServiceToken — same rationale as apiKeyShape's guard.
var _ = func() serviceTokenShape {
	var t types.ServiceToken
	return serviceTokenShape{
		Name:      t.Name,
		Namespace: t.Namespace,
		Service:   t.Service,
		Creation:  t.Creation,
		Source:    t.Source,
	}
}
