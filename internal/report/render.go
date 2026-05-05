package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/esops-dev/esops-doctor/internal/engine"
)

// Options is the format-agnostic shape of report-shaping flags. Each
// renderer interprets these the same way:
//
//   - SummaryOnly: emit only the cluster + scan + summary blocks; drop
//     per-rule rows. Wired to --summary-only.
//   - Quiet: drop pass and skipped rows from the per-rule output. Failing
//     and errored rows always survive — those are what an operator must
//     see. Summary counts always reflect the full result set. Wired to
//     --quiet (which also lowers the slog level via the logging init).
type Options struct {
	SummaryOnly bool
	Quiet       bool
}

// Render dispatches to the format-specific renderer. format is the
// already-validated value resolveOutput returned (lowercase, in the
// implemented set). Unknown values are a programmer error rather than
// user input — the cli's resolveOutput is the gatekeeper — so this
// returns a plain error rather than a usage error.
func Render(format string, w io.Writer, h Header, results []engine.RuleResult, opts Options) error {
	switch strings.ToLower(format) {
	case "", "table":
		// Options and TableOptions have identical fields — convert
		// directly so a future field addition only needs to land in
		// one struct (staticcheck S1016).
		return Table(w, h, results, TableOptions(opts))
	case "json":
		return JSON(w, h, results, opts)
	case "yaml":
		return YAML(w, h, results, opts)
	case "sarif":
		return SARIF(w, h, results, opts)
	case "junit":
		return JUnit(w, h, results, opts)
	case "html":
		return HTML(w, h, results, opts)
	default:
		return fmt.Errorf("output format %q not implemented", format)
	}
}
