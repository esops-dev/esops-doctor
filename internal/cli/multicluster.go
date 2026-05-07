package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/exit"
	"github.com/esops-dev/esops-doctor/internal/findings"
	"github.com/esops-dev/esops-doctor/internal/logging"
	"github.com/esops-dev/esops-doctor/internal/report"
	"github.com/esops-dev/esops-doctor/internal/waivers"
)

// runMultiClusterScan walks targets sequentially, runs the same engine
// + waiver set against each, and emits one fleet-wide report. Sequential
// is the deliberate first-release model (CLAUDE.md §17): parallel
// fan-out introduces resource budgets and per-cluster output ordering
// concerns better deferred until a real workload asks for them.
//
// Exit-code semantics, in priority order:
//
//  1. Findings ≥ --fail-on threshold on any cluster → exit 20.
//  2. Otherwise, if any cluster failed to connect → propagate the first
//     such error (exit 3 / 4 / 5 / 10 depending on the sentinel).
//  3. Otherwise, exit 0.
//
// Findings beat connect failures because the operator-actionable
// "the linter caught something" is the dominant reason a CI gate
// runs this command; an unreachable cluster mid-fleet should not
// mask a critical finding from a reachable one.
func runMultiClusterScan(
	ctx context.Context,
	stdout io.Writer,
	format string,
	opts report.Options,
	failOn findings.Severity,
	eng *engine.Engine,
	waiverSet *waivers.Set,
	targets []targetSpec,
) error {
	logging.Logger().Info("doctor.scan.multicluster.start", "count", len(targets))

	outcomes := make([]clusterOutcome, 0, len(targets))
	var firstConnectErr error
	for i, t := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		logging.Logger().Info("doctor.scan.multicluster.cluster",
			"index", i+1, "of", len(targets), "target", t.Label)
		out := scanOneCluster(ctx, eng, waiverSet, t)
		if out.connectErr != nil {
			logging.Logger().Warn("doctor.scan.multicluster.connect_failed",
				"target", t.Label, "err", out.connectErr)
			if firstConnectErr == nil {
				firstConnectErr = out.connectErr
			}
		}
		outcomes = append(outcomes, out)
	}

	clusters := buildClusterReports(outcomes)
	if err := report.RenderMulti(format, stdout, clusters, opts); err != nil {
		return fmt.Errorf("rendering multi-cluster report: %w", err)
	}

	if max := report.MaxFailingSeverityFleet(clusters); max >= failOn {
		// Silent so main does not double-print: the report has already
		// said what failed; the exit-code wrapper carries the marker.
		return exit.Silent(fmt.Errorf("%w: max severity=%s, threshold=%s",
			exit.ErrFindings, max, failOn))
	}
	if firstConnectErr != nil {
		// Propagate the first connect failure so the exit code reflects
		// the cluster-side problem (3/4/5/10). The other reachable
		// clusters' reports already rendered above; nothing is lost.
		return exit.Silent(firstConnectErr)
	}
	return nil
}

// buildClusterReports turns per-cluster outcomes into the wire shape
// the report layer renders. Outcomes whose connect failed render as
// an error block — the Header carries the operator-supplied target
// label so an unreachable cluster does not vanish from the report.
func buildClusterReports(outcomes []clusterOutcome) []report.ClusterReport {
	out := make([]report.ClusterReport, 0, len(outcomes))
	for _, o := range outcomes {
		cr := report.ClusterReport{
			Label:   o.Label,
			Header:  o.Header,
			Results: o.Results,
		}
		if o.connectErr != nil {
			cr.ConnectError = o.connectErr.Error()
			// classifyConnectErrLabel keeps the report's failure
			// messaging stable across formats: every renderer reads
			// ConnectErrorClass to decide which icon / level / kind to
			// show, instead of re-parsing the wrapped error chain.
			cr.ConnectErrorClass = classifyConnectErrLabel(o.connectErr)
		}
		// Make sure the cluster label is visible even when the connect
		// failed before pkg/cluster could fill in ClusterName/Version.
		if cr.Header.ClusterName == "" {
			cr.Header.ClusterName = o.Label
		}
		out = append(out, cr)
	}
	return out
}

// classifyConnectErrLabel returns the operator-facing class of a
// connect-time failure (`unreachable`, `auth`, `forbidden`,
// `unknown_product`, or `error`). Routes through the exit-package
// sentinels so the labels track the documented exit codes.
func classifyConnectErrLabel(err error) string {
	switch {
	case errors.Is(err, exit.ErrUnreachable):
		return "unreachable"
	case errors.Is(err, exit.ErrAuth):
		return "auth_failed"
	case errors.Is(err, exit.ErrForbidden):
		return "forbidden"
	case errors.Is(err, exit.ErrUnknownProduct):
		return "unknown_product"
	default:
		return "error"
	}
}
