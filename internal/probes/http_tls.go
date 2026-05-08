package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
)

// fetchHTTPTLS calls HTTPTLSInspector.HTTPTLS — the cluster-side view
// of HTTP-layer TLS posture. Sibling of the transport_tls probe: the
// transport layer is node-to-node, the HTTP layer is what every
// external client (esops, dashboards, application traffic) connects
// to. Used by doctor's http_tls rule.
//
// Result is a single object (not a list) shaped as types.HTTPTLSPosture:
// { enabled, client_auth, protocols, cipher_suites, per_node }. Enabled
// is true only when every reachable node reports HTTP TLS enabled, per
// the upstream's all-or-nothing aggregation contract — a single
// misconfigured node is exactly what the rule has to flag.
func fetchHTTPTLS(ctx context.Context, h client.HTTPTLSInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	view, err := h.HTTPTLS(ctx)
	if err != nil {
		return nil, fmt.Errorf("http_tls probe: %w", err)
	}
	return jsonShape("http_tls", view)
}
