package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain neuters the config-resolution environment for the whole
// package. Several tests run the root command, which fires the
// initLogger Before hook and calls config.Resolve / config.Parse. With
// the developer's real env in place, that lookup walks ESOPS_CONFIG →
// ./esops.yaml → $XDG_CONFIG_HOME/esops/config.yaml →
// ~/.config/esops/config.yaml and silently picks up the developer's
// personal esops config — which then bleeds into test state (wrong
// defaults, ./esops.log files written into the package directory,
// etc.). Pinning every relevant env var to an empty TempDir keeps the
// test run hermetic.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "esops-doctor-cli-test-home-")
	if err != nil {
		panic(err)
	}

	os.Setenv("ESOPS_CONFIG", "")
	os.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "xdg"))
	os.Setenv("HOME", filepath.Join(tmp, "home"))
	os.Setenv("USERPROFILE", filepath.Join(tmp, "home"))

	code := m.Run()
	_ = os.RemoveAll(tmp) // os.Exit skips defers, so clean up explicitly.
	os.Exit(code)
}
