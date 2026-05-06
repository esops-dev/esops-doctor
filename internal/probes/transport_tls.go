package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
)

// fetchTransportTLS calls TransportTLSInspector.TransportTLS — the
// cluster-side view of node-to-node transport TLS. Distinct from the
// security_audit probe's TLSPosture, which is HTTP-client-side facts
// the operator's local config owns. Used by doctor's
// node_to_node_encryption rule.
//
// Result is a single object (not a list) shaped as types.TransportTLS:
// { transport_tls_enabled, transport_tls_verified }. Enabled is true
// only when every reachable node reports transport TLS enabled, per
// the upstream's all-or-nothing aggregation contract — a single
// misconfigured node in a fleet is exactly what the rule has to flag.
func fetchTransportTLS(ctx context.Context, tt client.TransportTLSInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	view, err := tt.TransportTLS(ctx)
	if err != nil {
		return nil, fmt.Errorf("transport_tls probe: %w", err)
	}
	return jsonShape("transport_tls", view)
}
