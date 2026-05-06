// Package engine compiles rule CEL conditions and evaluates them
// against probe data. It is the single owner of CEL knowledge in the
// tree — the rules package is intentionally CEL-free so YAML schema
// validation does not require pulling in cel-go.
//
// Layering:
//
//   - rules: data + schema validation (no CEL)
//   - engine: CEL compile + evaluate, depends on rules
//   - cli: orchestrates rules.Validate + engine.Compile + engine.Evaluate
package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/cel-go/cel"

	"github.com/esops-dev/esops-doctor/internal/findings"
	"github.com/esops-dev/esops-doctor/internal/rules"
)

// compiledRule pairs a rule with its compiled CEL program. The rule is
// kept whole so message templating and dialect filtering at evaluate
// time don't need a second lookup. countProg is the optional
// count_expression program — nil when the rule did not declare one,
// in which case the message renderer falls back to len(self).
type compiledRule struct {
	rule      rules.Rule
	prog      cel.Program
	countProg cel.Program
}

// Engine is a compiled set of rules ready for repeated evaluation.
// Construct with Compile; never zero-initialised by callers.
type Engine struct {
	rules []compiledRule
	env   *cel.Env
}

// Rules returns the rules the engine was compiled with, in catalog
// order. Useful for reporting "rule X did not run" against the
// declared catalog rather than just the evaluated subset.
func (e *Engine) Rules() []rules.Rule {
	out := make([]rules.Rule, len(e.rules))
	for i, cr := range e.rules {
		out[i] = cr.rule
	}
	return out
}

// CompileError aggregates per-rule CEL compile failures so a caller
// gets every problem in one report instead of fixing them one at a
// time.
type CompileError struct {
	Failures []RuleCompileError
}

// RuleCompileError is one rule's compile failure. Source mirrors the
// rule loader's source attribution so the message points at the offending
// file.
type RuleCompileError struct {
	RuleID  string
	Source  string
	Message string
}

func (e *CompileError) Error() string {
	lines := make([]string, 0, len(e.Failures))
	for _, f := range e.Failures {
		switch {
		case f.Source != "" && f.RuleID != "":
			lines = append(lines, fmt.Sprintf("%s: rule %q: %s", f.Source, f.RuleID, f.Message))
		case f.RuleID != "":
			lines = append(lines, fmt.Sprintf("rule %q: %s", f.RuleID, f.Message))
		default:
			lines = append(lines, f.Message)
		}
	}
	return strings.Join(lines, "\n")
}

// Compile builds a CEL program for each rule's condition. The
// `self` variable is declared as dyn — probe data is JSON-shaped (maps
// and slices of any) and rules access fields through CEL's field
// resolution. The output type must be bool; a non-bool condition is a
// catalog bug, not a runtime condition, so it fails Compile.
//
// On any failure, every rule's compile error is collected before
// returning so an operator running validate-rules sees the whole
// problem set in one pass.
func Compile(catalog *rules.Catalog) (*Engine, error) {
	env, err := cel.NewEnv(cel.Variable("self", cel.DynType))
	if err != nil {
		return nil, fmt.Errorf("cel env: %w", err)
	}
	var compiled []compiledRule
	var failures []RuleCompileError

	for _, r := range catalog.Rules {
		ast, iss := env.Compile(r.Condition)
		if iss != nil && iss.Err() != nil {
			failures = append(failures, RuleCompileError{
				RuleID:  r.ID,
				Source:  r.Source,
				Message: iss.Err().Error(),
			})
			continue
		}
		if !ast.OutputType().IsAssignableType(cel.BoolType) {
			failures = append(failures, RuleCompileError{
				RuleID:  r.ID,
				Source:  r.Source,
				Message: fmt.Sprintf("condition must return bool, got %s", ast.OutputType()),
			})
			continue
		}
		prg, err := env.Program(ast)
		if err != nil {
			failures = append(failures, RuleCompileError{
				RuleID:  r.ID,
				Source:  r.Source,
				Message: fmt.Sprintf("program: %s", err),
			})
			continue
		}
		countProg, cerr := compileCountExpression(env, r)
		if cerr != nil {
			failures = append(failures, *cerr)
			continue
		}
		compiled = append(compiled, compiledRule{rule: r, prog: prg, countProg: countProg})
	}

	if len(failures) > 0 {
		return nil, &CompileError{Failures: failures}
	}
	return &Engine{rules: compiled, env: env}, nil
}

// compileCountExpression compiles r.CountExpression as a CEL program
// returning an int. Returns (nil, nil) when the rule has no
// expression — the message renderer falls back to len(self) in that
// case. CEL's `int` and `uint` both satisfy the integer-output check;
// we coerce to int64 at evaluate time.
func compileCountExpression(env *cel.Env, r rules.Rule) (cel.Program, *RuleCompileError) {
	if strings.TrimSpace(r.CountExpression) == "" {
		return nil, nil
	}
	ast, iss := env.Compile(r.CountExpression)
	if iss != nil && iss.Err() != nil {
		return nil, &RuleCompileError{
			RuleID:  r.ID,
			Source:  r.Source,
			Message: "count_expression: " + iss.Err().Error(),
		}
	}
	if !ast.OutputType().IsAssignableType(cel.IntType) &&
		!ast.OutputType().IsAssignableType(cel.UintType) {
		return nil, &RuleCompileError{
			RuleID:  r.ID,
			Source:  r.Source,
			Message: fmt.Sprintf("count_expression must return int, got %s", ast.OutputType()),
		}
	}
	prg, err := env.Program(ast)
	if err != nil {
		return nil, &RuleCompileError{
			RuleID:  r.ID,
			Source:  r.Source,
			Message: "count_expression program: " + err.Error(),
		}
	}
	return prg, nil
}

// RuleStatus is the outcome of evaluating one rule.
type RuleStatus int

// Status values; ordering is not meaningful and callers should not
// rely on the underlying integers.
const (
	RuleStatusPass RuleStatus = iota
	RuleStatusFail
	RuleStatusSkipped
	RuleStatusError
)

func (s RuleStatus) String() string {
	switch s {
	case RuleStatusPass:
		return "pass"
	case RuleStatusFail:
		return "fail"
	case RuleStatusSkipped:
		return "skipped"
	case RuleStatusError:
		return "error"
	default:
		return "unknown"
	}
}

// RuleResult is the per-rule outcome of an Evaluate call.
//
//   - Pass:    condition evaluated true; no Finding.
//   - Fail:    condition evaluated false; Finding populated.
//   - Skipped: rule was inapplicable (dialect mismatch, probe missing).
//     SkipReason carries the human-readable cause.
//   - Error:   probe fetch or CEL evaluation threw. Err carries the cause.
//
// Skipped is reported (not silent) per CLAUDE.md §3 so an operator
// sees that a rule was inapplicable rather than absent.
//
// Rule is the full rule definition, included so renderers can show
// rule metadata (name, category, severity, description, dialects,
// tags) on every status — not just on fails. This is what lets a
// passing-rule row carry useful context in json/yaml/sarif/junit/html
// output without the renderer having to look the rule up in the
// catalog by ID.
type RuleResult struct {
	RuleID     string
	Rule       rules.Rule
	Status     RuleStatus
	Finding    *findings.Finding
	SkipReason string
	Err        error
	Duration   time.Duration
}
