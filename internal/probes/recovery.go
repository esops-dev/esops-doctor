package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"
)

// fetchRecovery calls RecoveryInspector.Recovery for every index, with
// ActiveOnly so the report carries only shards still relocating /
// recovering — the rule audience cares about "what's still moving",
// not the historical record of completed recoveries.
//
// Result mirrors types.RecoveryReport (indices[], all_done) with each
// index entry holding shards[] of stage / source records.
func fetchRecovery(ctx context.Context, ri client.RecoveryInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	report, err := ri.Recovery(ctx, types.RecoveryRequest{
		Indices:    "_all",
		ActiveOnly: true,
	})
	if err != nil {
		return nil, fmt.Errorf("recovery probe: %w", err)
	}
	return jsonShape("recovery", report)
}
