package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
)

// fetchIndexTemplates lists every v2 (composable) index template via
// GetTemplates(nil) — passing nil lets the cluster return every entry.
// Legacy /_template entries are deliberately excluded upstream; both
// products consider them deprecated and surfacing both shapes would
// muddy the rule conditions.
func fetchIndexTemplates(ctx context.Context, it client.IndexTemplateInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tpls, err := it.GetTemplates(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("index_templates probe: %w", err)
	}
	return jsonShape("index_templates", tpls)
}
