package report

import (
	"fmt"
	"io"

	yaml "go.yaml.in/yaml/v3"

	"github.com/esops-dev/esops-doctor/internal/engine"
)

// YAML writes the report as YAML with two-space indent. Same schema as
// JSON (Document); the YAML encoder uses the same struct tags so a
// downstream that handles either format sees identical field names.
func YAML(w io.Writer, h Header, results []engine.RuleResult, opts Options) error {
	doc := BuildDocument(h, results, opts)
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encoding yaml report: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("closing yaml encoder: %w", err)
	}
	return nil
}
