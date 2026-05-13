package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/esops-dev/esops-doctor/internal/findings"
)

// staticEnv builds a getenv stub from a map so the resolver's
// env-var contract can be exercised without polluting the process
// environment.
func staticEnv(m map[string]string) func(string) string {
	return func(key string) string { return m[key] }
}

func TestResolveColorEnabled(t *testing.T) {
	// Non-file writer (bytes.Buffer): Auto -> false; CLICOLOR_FORCE
	// flips it on; --no-color (Disable) wins over CLICOLOR_FORCE;
	// NO_COLOR beats everything except Disable, which already wins.
	cases := []struct {
		name string
		pref ColorPreference
		env  map[string]string
		want bool
	}{
		{"auto on non-tty buffer", ColorAuto, nil, false},
		{"force overrides auto", ColorAuto, map[string]string{"CLICOLOR_FORCE": "1"}, true},
		{"no-color beats force", ColorDisable, map[string]string{"CLICOLOR_FORCE": "1"}, false},
		{"NO_COLOR beats force", ColorAuto, map[string]string{"CLICOLOR_FORCE": "1", "NO_COLOR": "1"}, false},
		{"CLICOLOR=0 disables auto", ColorAuto, map[string]string{"CLICOLOR": "0"}, false},
		{"explicit enable forces on", ColorEnable, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			got := ResolveColorEnabled(tc.pref, &buf, staticEnv(tc.env))
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestColorizeWrapsKnownSeverities verifies the table writer's
// severity-token wrapping. Unknown severities pass through unwrapped.
func TestColorizeWrapsKnownSeverities(t *testing.T) {
	if got := colorize("critical", findings.SeverityCritical, true); !strings.Contains(got, "\x1b[1;31m") {
		t.Errorf("critical should use bold-red; got %q", got)
	}
	if got := colorize("warn", findings.SeverityWarn, true); !strings.Contains(got, "\x1b[33m") {
		t.Errorf("warn should use yellow; got %q", got)
	}
	if got := colorize("warn", findings.SeverityWarn, false); got != "warn" {
		t.Errorf("color=false should round-trip the string; got %q", got)
	}
	if got := colorize("unknown", findings.SeverityUnknown, true); got != "unknown" {
		t.Errorf("unknown severity should not be wrapped; got %q", got)
	}
}
