package probes

import (
	"context"
	"fmt"
	"time"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"
)

// auditWarningsWindow is how far back the audit_warnings probe looks
// when no rule-side override is wired. 24h is the smallest useful
// scan window: long enough to catch the previous on-call shift's
// activity, short enough that a busy cluster's audit index does not
// drown the rule before the upstream Limit kicks in.
const auditWarningsWindow = 24 * time.Hour

// auditWarningsLimit caps the rows returned in the window. Picked
// well below the cluster's default page size so a chatty cluster
// can't blow the rule's evaluation budget on a single scan.
const auditWarningsLimit = 1000

// fetchAuditLog calls AuditLogInspector.AuditConfig — the cluster-side
// declaration of whether audit logging is on, where records ship, and
// what filters are applied. Used by doctor's audit_logging_enabled rule.
//
// Result is a single object (not a list) shaped as types.AuditConfig:
// { enabled, outputs, events_include, events_exclude, ignore_users }.
func fetchAuditLog(ctx context.Context, a client.AuditLogInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cfg, err := a.AuditConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("audit_log probe: %w", err)
	}
	return jsonShape("audit_log", cfg)
}

// fetchAuditWarnings tails AuditLogInspector.AuditWarnings over a
// fixed recent window. The window and limit are baked here so every
// rule that targets the audit_warnings probe sees the same slice
// within a scan; per-rule overrides would defeat the engine's
// once-per-scan caching of probe data.
//
// Result is a list of types.AuditWarning entries:
// [{ timestamp, layer, type, count }, ...]. An empty list is the
// happy path the rule passes on.
func fetchAuditWarnings(ctx context.Context, a client.AuditLogInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	req := types.AuditWarningsRequest{
		Since: time.Now().Add(-auditWarningsWindow),
		Limit: auditWarningsLimit,
	}
	warnings, err := a.AuditWarnings(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("audit_warnings probe: %w", err)
	}
	return jsonShape("audit_warnings", warnings)
}
