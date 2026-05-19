package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"
)

// fetchSegments calls SegmentsInspector.Segments across every index,
// returning the per-index aggregate view (segments_total,
// segments_primary, docs_total, docs_deleted, bytes,
// max_segments_shard) rules match on. One round-trip per scan,
// regardless of how many segments rules are enabled — the engine
// caches probe results per scan.
//
// Result mirrors types.SegmentsReport ({indices: []IndexSegments});
// rules read self.indices[*]. Filtering by index pattern stays at
// the rule layer (CEL filter() over self.indices) rather than the
// probe — same shape for every rule that consumes the data.
func fetchSegments(ctx context.Context, si client.SegmentsInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	report, err := si.Segments(ctx, types.SegmentsRequest{Indices: "_all"})
	if err != nil {
		return nil, fmt.Errorf("segments probe: %w", err)
	}
	return jsonShape("segments", report)
}
