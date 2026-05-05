package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/esops-dev/esops-doctor/internal/engine"
)

// JSON writes the report as pretty-printed JSON with a trailing
// newline. Pretty-print (two-space indent) so the output is reviewable
// in terminals and diffs; downstream tools that prefer compact form
// can still parse it with any standard JSON library.
//
// The schema is owned by Document — see SchemaVersion for the wire
// version contract.
func JSON(w io.Writer, h Header, results []engine.RuleResult, opts Options) error {
	doc := BuildDocument(h, results, opts)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encoding json report: %w", err)
	}
	return nil
}
