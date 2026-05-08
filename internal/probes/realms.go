package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
)

// fetchRealms calls RealmsInspector.Realms — the dialect-neutral view
// of the cluster's configured authentication realms. Used by doctor's
// deprecated_realms rule.
//
// Result is a list of types.Realm entries:
// [{ name, type, order, enabled, deprecated }, ...]. An empty list on
// a security-enabled cluster is unusual but not the rule's concern;
// the deprecated_realms rule passes on the empty case.
//
// OS-specific caveat documented upstream: a non-admin client hits a
// 403 on /_plugins/_security/api/securityconfig and the capability
// returns ErrForbidden, which surfaces as a probe error rather than
// an empty slice. Operators running the rule against OS without the
// admin TLS cert see a probe-error result, which the engine reports
// as Skipped/Error rather than a green pass.
func fetchRealms(ctx context.Context, r client.RealmsInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	realms, err := r.Realms(ctx)
	if err != nil {
		return nil, fmt.Errorf("realms probe: %w", err)
	}
	return jsonShape("realms", realms)
}
