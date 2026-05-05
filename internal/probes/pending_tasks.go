package probes

import (
	"context"
	"fmt"

	"github.com/esops-dev/esops-go/pkg/client"
)

// fetchPendingTasks calls PendingTasksInspector.PendingTasks — the
// per-task breakdown of /_cluster/pending_tasks. ClusterHealth gives a
// count via number_of_pending_tasks; this probe returns the actual
// queue (priority, source, time_in_queue_millis, executing) so a rule
// can tell a transient burst from a stuck master.
//
// JSON shape mirrors snake_case tags on types.PendingTask.
func fetchPendingTasks(ctx context.Context, pti client.PendingTasksInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tasks, err := pti.PendingTasks(ctx)
	if err != nil {
		return nil, fmt.Errorf("pending_tasks probe: %w", err)
	}
	return jsonShape("pending_tasks", tasks)
}
