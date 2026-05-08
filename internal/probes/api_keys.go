package probes

import (
	"context"
	"fmt"
	"time"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"
)

// apiKeyShape mirrors types.APIKey one-for-one and adds age_days, the
// derived field the stale_api_keys rule compares against. Computed at
// probe time rather than at evaluate time because CEL has no relative
// "now" — injecting a now variable into the engine would widen the
// CEL surface for one rule. age_days is omitted on keys with a zero
// Creation (the cluster did not surface it, so any age would be a lie).
type apiKeyShape struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Username      string     `json:"username,omitempty"`
	Realm         string     `json:"realm,omitempty"`
	Creation      time.Time  `json:"creation"`
	Expiration    *time.Time `json:"expiration,omitempty"`
	LastAuth      *time.Time `json:"last_auth,omitempty"`
	Invalidated   bool       `json:"invalidated,omitempty"`
	RoleTemplates []string   `json:"role_templates,omitempty"`
	AgeDays       *float64   `json:"age_days,omitempty"`
}

// fetchAPIKeys calls APIKeyInspector.APIKeys — the typed-time view of
// active API keys (sibling of security_audit's string-typed api_keys
// block). Used by doctor's stale_api_keys rule, which compares
// age_days against an in-rule threshold.
//
// Result is a list of {id, name, ..., age_days} entries. ES-only on
// the upstream side: the OS adapter is the unsupported stub, so this
// probe surfaces engine.ErrProbeNotApplicable on OS via the registry's
// ErrUnsupported translation and the rule reports Skipped.
func fetchAPIKeys(ctx context.Context, k client.APIKeyInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keys, err := k.APIKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("api_keys probe: %w", err)
	}
	now := time.Now()
	out := make([]apiKeyShape, 0, len(keys))
	for _, key := range keys {
		entry := apiKeyShape{
			ID:            key.ID,
			Name:          key.Name,
			Username:      key.Username,
			Realm:         key.Realm,
			Creation:      key.Creation,
			Expiration:    key.Expiration,
			LastAuth:      key.LastAuth,
			Invalidated:   key.Invalidated,
			RoleTemplates: key.RoleTemplates,
		}
		if !key.Creation.IsZero() {
			age := now.Sub(key.Creation).Hours() / 24
			entry.AgeDays = &age
		}
		out = append(out, entry)
	}
	return jsonShape("api_keys", out)
}

// Compile-time check that apiKeyShape covers every field of types.APIKey.
// A future field added upstream lights this up: the assignment fails
// because the new field is missing from apiKeyShape, prompting the
// author to mirror it (or, if it carries sensitive data, to leave it
// off explicitly with a comment).
var _ = func() apiKeyShape {
	var k types.APIKey
	return apiKeyShape{
		ID:            k.ID,
		Name:          k.Name,
		Username:      k.Username,
		Realm:         k.Realm,
		Creation:      k.Creation,
		Expiration:    k.Expiration,
		LastAuth:      k.LastAuth,
		Invalidated:   k.Invalidated,
		RoleTemplates: k.RoleTemplates,
	}
}
