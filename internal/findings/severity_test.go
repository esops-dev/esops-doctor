package findings

import (
	"errors"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

func TestSeverityOrdering(t *testing.T) {
	// info < warn < error < critical is the contract that --fail-on
	// will rely on. SeverityUnknown sits below info so a missing
	// severity never accidentally trips a threshold.
	want := []Severity{SeverityUnknown, SeverityInfo, SeverityWarn, SeverityError, SeverityCritical}
	for i := 1; i < len(want); i++ {
		if want[i-1] >= want[i] {
			t.Errorf("expected %v < %v", want[i-1], want[i])
		}
	}
}

func TestSeverityString(t *testing.T) {
	cases := map[Severity]string{
		SeverityUnknown:  "",
		SeverityInfo:     "info",
		SeverityWarn:     "warn",
		SeverityError:    "error",
		SeverityCritical: "critical",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("Severity(%d).String() = %q, want %q", int(s), got, want)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want Severity
	}{
		{"info", SeverityInfo},
		{"INFO", SeverityInfo},
		{"  warn ", SeverityWarn},
		{"warning", SeverityWarn},
		{"error", SeverityError},
		{"critical", SeverityCritical},
	}
	for _, c := range cases {
		got, err := ParseSeverity(c.in)
		if err != nil {
			t.Errorf("ParseSeverity(%q) errored: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseSeverityRejectsUnknown(t *testing.T) {
	_, err := ParseSeverity("fatal")
	if err == nil {
		t.Fatal("expected error for unknown severity")
	}
}

func TestSeverityYAMLRoundTrip(t *testing.T) {
	// Round-trip every named severity through marshal+unmarshal so a
	// future refactor that breaks one direction breaks here loudly.
	for _, s := range []Severity{SeverityInfo, SeverityWarn, SeverityError, SeverityCritical} {
		data, err := yaml.Marshal(s)
		if err != nil {
			t.Fatalf("yaml.Marshal(%v): %v", s, err)
		}
		var got Severity
		if err := yaml.Unmarshal(data, &got); err != nil {
			t.Fatalf("yaml.Unmarshal(%q): %v", string(data), err)
		}
		if got != s {
			t.Errorf("round-trip: %v -> %q -> %v", s, data, got)
		}
	}
}

func TestSeverityYAMLRejectsUnknownLevel(t *testing.T) {
	var s Severity
	err := yaml.Unmarshal([]byte("fatal\n"), &s)
	if err == nil {
		t.Fatal("expected error for unknown severity in YAML")
	}
}

func TestSeverityYAMLRejectsNonScalar(t *testing.T) {
	// `severity: [critical]` is a typo that must not silently coerce
	// into SeverityUnknown — that would mask the broken rule.
	var s Severity
	err := yaml.Unmarshal([]byte("[critical]\n"), &s)
	if err == nil {
		t.Fatal("expected error for sequence input")
	}
}

func TestSeverityMarshalUnknownIsError(t *testing.T) {
	_, err := yaml.Marshal(SeverityUnknown)
	if err == nil {
		t.Fatal("expected error marshaling SeverityUnknown")
	}
	// Sanity: not a typed error users have to catch — just non-nil.
	if errors.Is(err, nil) {
		t.Error("err should be non-nil")
	}
}
