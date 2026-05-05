package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
)

// fetchSecurityAudit calls SecurityAuditor.Audit. The capability hides
// the dialect split (ES native realm vs. OS security plugin) behind a
// neutral SecurityReport; rules see one shape across both products.
//
// When the cluster has no security in play (ES with security disabled,
// OS without the plugin), the upstream returns Status.Enabled=false
// rather than an error — that's a valid audit outcome a rule may want
// to flag, not a probe failure.
func fetchSecurityAudit(ctx context.Context, sa client.SecurityAuditor) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	report, err := sa.Audit(ctx)
	if err != nil {
		return nil, fmt.Errorf("security_audit probe: %w", err)
	}
	return jsonShape("security_audit", report)
}
