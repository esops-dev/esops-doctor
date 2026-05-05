package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

// runWithFlags runs the root command capturing the parsed *cli.Command for
// inspection. The returned *cli.Command is the subcommand that fired (here
// always 'version'), with flags inherited from the root.
func runWithFlags(t *testing.T, args ...string) *cli.Command {
	t.Helper()
	root := newRoot()
	// Replace the version action with a capture so we can inspect flag state.
	for _, c := range root.Commands {
		if c.Name == "version" {
			c.Action = func(_ context.Context, cmd *cli.Command) error { return nil }
		}
	}
	if err := root.Run(context.Background(), append([]string{"esops-doctor"}, args...)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	return root
}

func TestGlobalFlagsRegistered(t *testing.T) {
	flags := globalFlags()
	want := map[string]bool{
		"config":       false,
		"context":      false,
		"url":          false,
		"cacert":       false,
		"insecure":     false,
		"output":       false,
		"quiet":        false,
		"summary-only": false,
		"log-level":    false,
		"log-format":   false,
		"log-file":     false,
	}
	for _, f := range flags {
		for _, name := range f.Names() {
			if _, ok := want[name]; ok {
				want[name] = true
			}
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("global flag %q not registered", name)
		}
	}
}

func TestGlobalFlagAliases(t *testing.T) {
	flags := globalFlags()
	aliases := map[string]string{
		"c":       "config",
		"cluster": "context",
		"o":       "output",
	}
	for alias, primary := range aliases {
		found := false
		for _, f := range flags {
			names := f.Names()
			has := func(n string) bool {
				for _, x := range names {
					if x == n {
						return true
					}
				}
				return false
			}
			if has(primary) && has(alias) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("flag %q missing alias %q", primary, alias)
		}
	}
}

func TestQuietResolvesToValidLogLevel(t *testing.T) {
	// --quiet is shorthand for --log-level error. The Before hook
	// (initLogger) calls logging.Init with the resolved level; if --quiet
	// resolved to something logging couldn't parse, Run would fail here.
	runWithFlags(t, "--quiet", "version")
}

func TestRootRejectsBadLogLevel(t *testing.T) {
	err := Run(context.Background(), []string{"esops-doctor", "--log-level", "trace", "version"})
	if err == nil {
		t.Fatal("expected error for bogus --log-level")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("error should be ErrUsage so main exits 2; got %v", err)
	}
	if !exit.IsSilent(err) {
		t.Error("validator failure should be silent (urfave already printed); main would double-print otherwise")
	}
}

func TestRootRejectsBadLogFormat(t *testing.T) {
	err := Run(context.Background(), []string{"esops-doctor", "--log-format", "yaml", "version"})
	if err == nil {
		t.Fatal("expected error for bogus --log-format")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("error should be ErrUsage; got %v", err)
	}
}

func TestRootRejectsBadOutput(t *testing.T) {
	err := Run(context.Background(), []string{"esops-doctor", "--output", "csv", "version"})
	if err == nil {
		t.Fatal("expected error for bogus --output")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("error should be ErrUsage; got %v", err)
	}
}

func TestRootRejectsUnknownFlag(t *testing.T) {
	err := Run(context.Background(), []string{"esops-doctor", "--bogus", "version"})
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("urfave's 'flag provided but not defined' should map to ErrUsage; got %v", err)
	}
}

func TestRootBadLogFileIsUsageError(t *testing.T) {
	err := Run(context.Background(), []string{
		"esops-doctor",
		"--log-file", filepath.Join(t.TempDir(), "missing-dir", "doctor.log"),
		"version",
	})
	if err == nil {
		t.Fatal("expected error for unwritable --log-file")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("logging.Init failure should map to ErrUsage; got %v", err)
	}
	if exit.IsSilent(err) {
		t.Error("Before-hook usage error should NOT be silent — urfave didn't print it, main must")
	}
}

func TestRootHelpDoesNotErrorOnGoodFlags(t *testing.T) {
	// --help should not surface a usage error when global flags are valid.
	if err := Run(context.Background(), []string{"esops-doctor", "--help"}); err != nil {
		t.Errorf("--help unexpectedly returned an error: %v", err)
	}
}

func TestResolveLogLevelExplicitWins(t *testing.T) {
	root := newRoot()
	var got string
	for _, c := range root.Commands {
		if c.Name == "version" {
			c.Action = func(_ context.Context, cmd *cli.Command) error {
				got = resolveLogLevel(cmd, "warn")
				return nil
			}
		}
	}
	if err := root.Run(context.Background(), []string{"esops-doctor", "--log-level", "debug", "--quiet", "version"}); err != nil {
		t.Fatal(err)
	}
	if got != "debug" {
		t.Errorf("resolveLogLevel = %q, want debug (explicit --log-level wins over --quiet and config)", got)
	}
}

func TestResolveLogLevelQuietBeatsConfig(t *testing.T) {
	root := newRoot()
	var got string
	for _, c := range root.Commands {
		if c.Name == "version" {
			c.Action = func(_ context.Context, cmd *cli.Command) error {
				got = resolveLogLevel(cmd, "warn")
				return nil
			}
		}
	}
	if err := root.Run(context.Background(), []string{"esops-doctor", "--quiet", "version"}); err != nil {
		t.Fatal(err)
	}
	if got != "error" {
		t.Errorf("resolveLogLevel = %q, want error (--quiet beats config)", got)
	}
}

func TestResolveLogLevelConfigFallback(t *testing.T) {
	root := newRoot()
	var got string
	for _, c := range root.Commands {
		if c.Name == "version" {
			c.Action = func(_ context.Context, cmd *cli.Command) error {
				got = resolveLogLevel(cmd, "warn")
				return nil
			}
		}
	}
	if err := root.Run(context.Background(), []string{"esops-doctor", "version"}); err != nil {
		t.Fatal(err)
	}
	if got != "warn" {
		t.Errorf("resolveLogLevel = %q, want warn (from config)", got)
	}
}

func TestResolveLogLevelBuiltinDefault(t *testing.T) {
	root := newRoot()
	var got string
	for _, c := range root.Commands {
		if c.Name == "version" {
			c.Action = func(_ context.Context, cmd *cli.Command) error {
				got = resolveLogLevel(cmd, "")
				return nil
			}
		}
	}
	if err := root.Run(context.Background(), []string{"esops-doctor", "version"}); err != nil {
		t.Fatal(err)
	}
	if got != "info" {
		t.Errorf("resolveLogLevel = %q, want info (built-in default)", got)
	}
}

func TestDefaultLogFormat(t *testing.T) {
	t.Setenv("CI", "")
	if got := defaultLogFormat(); got != "text" {
		t.Errorf("defaultLogFormat without CI = %q, want text", got)
	}
	t.Setenv("CI", "true")
	if got := defaultLogFormat(); got != "json" {
		t.Errorf("defaultLogFormat with CI=true = %q, want json", got)
	}
	t.Setenv("CI", "1")
	if got := defaultLogFormat(); got != "json" {
		t.Errorf("defaultLogFormat with CI=1 = %q, want json", got)
	}
}

func TestReadDefaultsFromConfig(t *testing.T) {
	body := "defaults:\n  log_level: warn\n  log_format: json\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	d := readDefaults(path)
	if d.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want warn", d.LogLevel)
	}
	if d.LogFormat != "json" {
		t.Errorf("LogFormat = %q, want json", d.LogFormat)
	}
}

func TestWrapUsageError(t *testing.T) {
	cases := []struct {
		name       string
		in         error
		wantUsage  bool // errors.Is(err, ErrUsage)
		wantSilent bool // urfave already printed → main should skip
	}{
		{"nil passes through", nil, false, false},
		{"non-urfave usage err passes through, NOT silent", exit.Usage("log-file open failed"), true, false},
		{"required flag → usage + silent", errors.New(`Required flag "config" not set`), true, true},
		{"unknown flag → usage + silent", errors.New("flag provided but not defined: -bogus"), true, true},
		{"missing argument → usage + silent", errors.New("flag needs an argument: -config"), true, true},
		{"validator invalid value → usage + silent", errors.New(`invalid value "trace" for flag --log-level`), true, true},
		{"unrelated error stays as-is", errors.New("connection refused"), false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := wrapUsageError(c.in)
			if c.in == nil {
				if got != nil {
					t.Errorf("wrapUsageError(nil) = %v, want nil", got)
				}
				return
			}
			if isUsage := errors.Is(got, exit.ErrUsage); isUsage != c.wantUsage {
				t.Errorf("errors.Is(ErrUsage) = %v, want %v (err: %v)", isUsage, c.wantUsage, got)
			}
			if isSilent := exit.IsSilent(got); isSilent != c.wantSilent {
				t.Errorf("IsSilent = %v, want %v (err: %v)", isSilent, c.wantSilent, got)
			}
		})
	}
}

func TestValidatorsReturnUsage(t *testing.T) {
	for _, c := range []struct {
		name string
		fn   func(string) error
		bad  string
	}{
		{"log-level", validateLogLevel, "trace"},
		{"log-format", validateLogFormat, "yaml"},
		{"output", validateOutput, "csv"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.fn(c.bad)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, exit.ErrUsage) {
				t.Errorf("validator should return ErrUsage; got %v", err)
			}
			if !strings.Contains(err.Error(), c.bad) {
				t.Errorf("error should mention bad value %q; got %v", c.bad, err)
			}
		})
	}
}

func TestValidatorsAcceptValid(t *testing.T) {
	for _, s := range []string{"", "debug", "info", "warn", "error"} {
		if err := validateLogLevel(s); err != nil {
			t.Errorf("validateLogLevel(%q) returned %v", s, err)
		}
	}
	for _, s := range []string{"", "text", "json"} {
		if err := validateLogFormat(s); err != nil {
			t.Errorf("validateLogFormat(%q) returned %v", s, err)
		}
	}
	for _, s := range []string{"", "table"} {
		if err := validateOutput(s); err != nil {
			t.Errorf("validateOutput(%q) returned %v", s, err)
		}
	}
}

// TestValidateOutputRejectsPlannedFormats asserts that --output values
// CLAUDE.md §10 promises but Milestone 3 hasn't landed yet (json, yaml,
// sarif, junit, html) fail loudly with a usage error, rather than
// silently rendering a table. The error message mentions the milestone
// so an operator who reads CLAUDE.md and tries the format isn't
// confused about whether they typed it wrong or it's not built yet.
func TestValidateOutputRejectsPlannedFormats(t *testing.T) {
	for _, s := range []string{"json", "yaml", "sarif", "junit", "html"} {
		err := validateOutput(s)
		if err == nil {
			t.Errorf("validateOutput(%q) accepted; expected usage error", s)
			continue
		}
		if !strings.Contains(err.Error(), "not yet implemented") {
			t.Errorf("validateOutput(%q) message = %q, want 'not yet implemented'", s, err)
		}
	}
}

func TestValidateOutputRejectsUnknown(t *testing.T) {
	err := validateOutput("xml")
	if err == nil {
		t.Fatal("validateOutput(\"xml\") accepted; expected usage error")
	}
	if strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("unknown format should not name Milestone 3; got %q", err)
	}
}

func TestReadDefaultsMissingFileIsZero(t *testing.T) {
	// TestMain already neuters ESOPS_CONFIG, HOME, USERPROFILE, and
	// XDG_CONFIG_HOME so the lookup chain can't reach the developer's
	// real ~/.config/esops/config.yaml. We still need to escape the
	// package directory so an ./esops.yaml from cwd can't satisfy the
	// search either.
	t.Chdir(t.TempDir()) // no ./esops.yaml
	d := readDefaults("")
	if d.LogLevel != "" || d.LogFormat != "" {
		t.Errorf("readDefaults without config = %+v, want zero", d)
	}
}
