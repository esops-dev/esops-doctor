package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"
)

// fetchDeprecations calls DeprecationInspector.Deprecations with an
// empty request — every category the cluster knows about across cluster,
// node, index, ML, data-stream, template, and ILM-policy issues. ES-only;
// the OS adapter returns client.ErrUnsupported, which the registry
// translates to engine.ErrProbeNotApplicable so the rule is reported as
// Skipped with a dialect-specific reason rather than RuleStatusError.
//
// Result mirrors types.DeprecationIssue: each issue carries
// category/target/level/message plus optional url/details/meta and the
// resolve_during_rolling_upgrade flag. Rules grade severity off the
// cluster's own "critical" / "warning" / "info" / "none" verbatim
// strings.
func fetchDeprecations(ctx context.Context, di client.DeprecationInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	issues, err := di.Deprecations(ctx, types.DeprecationsRequest{})
	if err != nil {
		return nil, fmt.Errorf("deprecation_log probe: %w", err)
	}
	return jsonShape("deprecation_log", issues)
}
