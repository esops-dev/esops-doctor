package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"
)

// fetchIndexSettings calls IndexSettingsInspector.GetSettings across
// every index. Defaults are excluded — they bloat the payload by an
// order of magnitude and rules looking for "drift" against a default
// don't gain anything from seeing the default duplicated on every
// index. A rule that needs defaults can request them through a
// dedicated probe in a future iteration.
//
// Indices=[] is rejected by the upstream as ambiguous, so we send the
// explicit "*" wildcard to mean "every index".
func fetchIndexSettings(ctx context.Context, isi client.IndexSettingsInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	settings, err := isi.GetSettings(ctx, types.IndexSettingsGetRequest{
		Indices:           []string{"*"},
		IgnoreUnavailable: true,
	})
	if err != nil {
		return nil, fmt.Errorf("index_settings probe: %w", err)
	}
	return jsonShape("index_settings", settings)
}
