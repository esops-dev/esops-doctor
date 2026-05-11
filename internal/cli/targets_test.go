package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

// fakeTargetsCmd implements the small interface resolveMultiTargets
// reads from cli.Command (StringSlice / String / Bool / IsSet). The
// real *cli.Command depends on the urfave parser, which we can drive
// through newRoot().Run, but resolveMultiTargets has a structured
// signature precisely to be unit-testable without that machinery.
type fakeTargetsCmd struct {
	targets []string
	url     string
	context string
	config  string
	cacert  string

	insecure       bool
	insecureWasSet bool
}

func (f fakeTargetsCmd) StringSlice(name string) []string {
	if name == "targets" {
		return f.targets
	}
	return nil
}

func (f fakeTargetsCmd) String(name string) string {
	switch name {
	case "url":
		return f.url
	case "context":
		return f.context
	case "config":
		return f.config
	case "cacert":
		return f.cacert
	}
	return ""
}

func (f fakeTargetsCmd) Bool(name string) bool {
	if name == "insecure" {
		return f.insecure
	}
	return false
}

func (f fakeTargetsCmd) IsSet(name string) bool {
	if name == "insecure" {
		return f.insecureWasSet
	}
	return false
}

const multiTargetsConfigYAML = `current-context: dev

contexts:
  dev:
    url: http://dev.example:9200
    protection: none
  staging:
    url: http://staging.example:9200
    protection: none
  prod:
    url: http://prod.example:9200
    protection: none
`

// writeTargetsConfig drops the canned multi-target config in a temp
// dir and returns its path. Reuses writeTestConfig (defined in
// config_get_contexts_test.go) so every config-touching test goes
// through the same mode-0600 helper.
func writeTargetsConfig(t *testing.T) string {
	t.Helper()
	return writeTestConfig(t, multiTargetsConfigYAML)
}

func TestResolveMultiTargetsEmpty(t *testing.T) {
	specs, isMulti, err := resolveMultiTargets(fakeTargetsCmd{})
	if err != nil {
		t.Fatalf("empty targets unexpected error: %v", err)
	}
	if isMulti {
		t.Error("isMulti should be false when --targets is empty")
	}
	if specs != nil {
		t.Errorf("specs should be nil; got %v", specs)
	}
}

func TestResolveMultiTargetsRejectsURL(t *testing.T) {
	cfgPath := writeTargetsConfig(t)
	_, isMulti, err := resolveMultiTargets(fakeTargetsCmd{
		targets: []string{"dev"},
		url:     "http://override:9200",
		config:  cfgPath,
	})
	if err == nil {
		t.Fatal("expected usage error")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("err is not ErrUsage: %v", err)
	}
	if !isMulti {
		t.Error("isMulti should be true (multi-cluster mode was requested)")
	}
}

func TestResolveMultiTargetsRejectsContext(t *testing.T) {
	cfgPath := writeTargetsConfig(t)
	_, _, err := resolveMultiTargets(fakeTargetsCmd{
		targets: []string{"dev"},
		context: "dev",
		config:  cfgPath,
	})
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("expected ErrUsage, got %v", err)
	}
}

func TestResolveMultiTargetsResolves(t *testing.T) {
	cfgPath := writeTargetsConfig(t)
	specs, isMulti, err := resolveMultiTargets(fakeTargetsCmd{
		targets: []string{"dev", "prod"},
		config:  cfgPath,
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !isMulti {
		t.Error("isMulti should be true")
	}
	if len(specs) != 2 {
		t.Fatalf("want 2 specs, got %d", len(specs))
	}
	if specs[0].Label != "dev" || specs[1].Label != "prod" {
		t.Errorf("labels in wrong order: %q, %q", specs[0].Label, specs[1].Label)
	}
	if specs[0].Context.URL != "http://dev.example:9200" {
		t.Errorf("dev URL not resolved: %q", specs[0].Context.URL)
	}
}

func TestResolveMultiTargetsDedupes(t *testing.T) {
	cfgPath := writeTargetsConfig(t)
	specs, _, err := resolveMultiTargets(fakeTargetsCmd{
		targets: []string{"dev", "dev", " dev "},
		config:  cfgPath,
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(specs) != 1 {
		t.Errorf("dup-collapse failed: %d specs, want 1", len(specs))
	}
}

func TestResolveMultiTargetsUnknownContext(t *testing.T) {
	cfgPath := writeTargetsConfig(t)
	_, _, err := resolveMultiTargets(fakeTargetsCmd{
		targets: []string{"bogus"},
		config:  cfgPath,
	})
	if !errors.Is(err, exit.ErrUsage) {
		t.Fatalf("expected ErrUsage, got %v", err)
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("error %q does not mention the bad context", err.Error())
	}
}

func TestResolveMultiTargetsAllWhitespace(t *testing.T) {
	cfgPath := writeTargetsConfig(t)
	_, _, err := resolveMultiTargets(fakeTargetsCmd{
		targets: []string{"", "  ", "\t"},
		config:  cfgPath,
	})
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("expected ErrUsage, got %v", err)
	}
}

func TestResolveMultiTargetsTLSOverride(t *testing.T) {
	cfgPath := writeTargetsConfig(t)
	specs, _, err := resolveMultiTargets(fakeTargetsCmd{
		targets:        []string{"dev"},
		config:         cfgPath,
		cacert:         "/tmp/ca.crt",
		insecure:       true,
		insecureWasSet: true,
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if specs[0].Context.TLS.CACert != "/tmp/ca.crt" {
		t.Errorf("cacert not applied: %q", specs[0].Context.TLS.CACert)
	}
	if !specs[0].Context.TLS.Insecure {
		t.Error("insecure override not applied")
	}
}
