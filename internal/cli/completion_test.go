package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRenderCompletionSubstitutesAppName(t *testing.T) {
	in := "complete -F __{{APP}}_bash_autocomplete {{APP}}\n"
	out := renderCompletion(in, "esops-doctor")
	if strings.Contains(out, "{{APP}}") {
		t.Errorf("placeholder still present after render: %q", out)
	}
	want := "complete -F __esops-doctor_bash_autocomplete esops-doctor\n"
	if out != want {
		t.Errorf("rendered = %q, want %q", out, want)
	}
}

// TestCompletionEmitsForEveryShell asserts every entry in
// completionScripts (bash, zsh, fish, pwsh) renders a non-empty
// script free of unsubstituted placeholders. The bash/zsh/fish
// templates carry {{APP}} and must be replaced; pwsh derives the
// command name from its own filename at sourcing time and does
// not carry the placeholder, so the app-name check applies only
// to the three substituting shells.
func TestCompletionEmitsForEveryShell(t *testing.T) {
	appSubstitutingShells := map[string]bool{"bash": true, "zsh": true, "fish": true}
	for shell, tmpl := range completionScripts {
		if tmpl == "" {
			t.Errorf("template for %s is empty", shell)
			continue
		}
		rendered := renderCompletion(tmpl, "esops-doctor")
		if strings.Contains(rendered, "{{APP}}") {
			t.Errorf("%s template still carries {{APP}} after render", shell)
		}
		if appSubstitutingShells[shell] && !strings.Contains(rendered, "esops-doctor") {
			t.Errorf("%s output does not mention the app name; renderer changed?", shell)
		}
	}
}

func TestCompletionRoundTripViaRoot(t *testing.T) {
	appSubstitutingShells := map[string]bool{"bash": true, "zsh": true, "fish": true}
	for _, shell := range []string{"bash", "zsh", "fish", "pwsh"} {
		t.Run(shell, func(t *testing.T) {
			var stdout bytes.Buffer
			root := newRoot()
			root.Writer = &stdout
			if err := root.Run(context.Background(), []string{"esops-doctor", "completion", shell}); err != nil {
				t.Fatalf("completion %s: %v", shell, err)
			}
			out := stdout.String()
			if out == "" {
				t.Fatalf("empty output for %s", shell)
			}
			if strings.Contains(out, "{{APP}}") {
				t.Errorf("rendered %s script still contains {{APP}}", shell)
			}
			if appSubstitutingShells[shell] && !strings.Contains(out, "esops-doctor") {
				t.Errorf("rendered %s script does not name the app", shell)
			}
		})
	}
}

func TestCompletionRejectsUnknownShell(t *testing.T) {
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	err := root.Run(context.Background(), []string{"esops-doctor", "completion", "ksh"})
	if err == nil {
		t.Fatal("expected error for unknown shell")
	}
	if !strings.Contains(err.Error(), "ksh") {
		t.Errorf("error %q does not mention the unknown shell name", err.Error())
	}
}
