package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// MaxStrippedBinarySize is the upper bound (in bytes) the release-shape
// binary may exceed before the budget test fires. CLAUDE.md §11 calls
// for ~35–45 MB stripped; the value here is generous because cel-go +
// protobuf + AWS SDK transitive costs mean a fresh dep bump can drift
// the number by a few MB without anything misconfigured. The test's job
// is to catch creep, not to police every kilobyte.
//
// Bumping this is a signal to do a dependency audit (`go build -ldflags
// "-w" -o /dev/null` then `go tool nm | sort | uniq -c | sort -nr`)
// before relaxing the budget — every step up should be a deliberate
// trade-off, not a quiet PR-by-PR drift.
const MaxStrippedBinarySize = 75 * 1024 * 1024 // 75 MB

// TestBinaryBudget builds the release-shape binary (stripped, trimpath)
// and asserts the resulting file is under MaxStrippedBinarySize. The
// test is gated on -short so a developer running `go test -short ./...`
// for a quick check skips the multi-second build.
//
// CLAUDE.md §11 documents the headline ~35–45 MB target. The current
// budget here is wider because the release toolchain has not yet
// run a dep audit; treat any growth past today's number as something
// to investigate before merging.
func TestBinaryBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary build in short mode")
	}
	bin := buildReleaseBinary(t)
	info, err := os.Stat(bin)
	if err != nil {
		t.Fatalf("stat binary: %v", err)
	}
	if info.Size() > MaxStrippedBinarySize {
		t.Errorf("stripped binary is %d bytes (%.1f MB); budget is %d bytes (%.1f MB) — investigate the dep audit before raising the limit",
			info.Size(), float64(info.Size())/(1024*1024),
			int64(MaxStrippedBinarySize), float64(MaxStrippedBinarySize)/(1024*1024))
	}
}

// TestBinaryBoundaryNoEsopsInternalSymbols asserts the linked binary
// contains no symbols from `esops-go/internal/...`. The Go module
// system already forbids importing internal packages, so a hit here
// would mean the upstream `pkg/...` surface accidentally re-exported
// or transitively dragged an internal type into the binary's symbol
// table — which would mean doctor is silently linking against
// implementation it has no contract on.
//
// The test parses the output of `go tool nm` on a -trimpath build (no
// -s -w, so the symbol table survives). A future change that swaps
// `pkg/cluster` construction for an `internal/cluster` import would
// fail here loudly.
func TestBinaryBoundaryNoEsopsInternalSymbols(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary build in short mode")
	}
	bin := buildBinaryWithSymbols(t)

	cmd := exec.Command("go", "tool", "nm", bin)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("go tool nm: %v\n%s", err, out.String())
	}

	const banned = "github.com/esops-dev/esops-go/internal"
	var hits []string
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Contains(line, banned) {
			hits = append(hits, strings.TrimSpace(line))
		}
	}
	if len(hits) > 0 {
		// Truncate the dump so a regression doesn't paper the failure
		// with thousands of lines. The first few are enough to point
		// at the leak.
		const max = 8
		shown := hits
		if len(shown) > max {
			shown = shown[:max]
		}
		t.Fatalf("found %d symbol(s) from esops-go/internal/...; first %d:\n  %s\n\nthis breaks the read-only-by-construction guarantee — route through pkg/client",
			len(hits), len(shown), strings.Join(shown, "\n  "))
	}
}

// buildReleaseBinary compiles cmd/esops-doctor with the release-shape
// flags (-trimpath, -ldflags -s -w, CGO_ENABLED=0) and returns the
// path of the resulting binary. The binary is written under t.TempDir
// so the runtime cleans it up; nothing is written into the workspace.
func buildReleaseBinary(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "esops-doctor-budget")
	return runGoBuild(t, []string{"build", "-trimpath", "-ldflags", "-s -w", "-o", out, "./cmd/esops-doctor"})
}

// buildBinaryWithSymbols compiles cmd/esops-doctor with -trimpath but
// without -s -w so the symbol table survives for `go tool nm`. The
// binary lands under t.TempDir; release shipping uses the stripped
// build, this one is for the boundary check only.
func buildBinaryWithSymbols(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "esops-doctor-symbols")
	return runGoBuild(t, []string{"build", "-trimpath", "-o", out, "./cmd/esops-doctor"})
}

// runGoBuild runs `go build` from the module root with the given args
// and CGO_ENABLED=0. Returns the output path. Skips the test when the
// build environment cannot find the module root (rare; only happens
// in unusual sandboxes). The helper always expects args ordered as
// [..., "-o", outPath, mainPkg] so we can derive the output path
// from the args slice without threading it as a separate parameter.
func runGoBuild(t *testing.T, args []string) string {
	t.Helper()
	root, err := moduleRoot()
	if err != nil {
		t.Skipf("cannot resolve module root: %v", err)
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build (%s): %v\n%s", strings.Join(args, " "), err, combined.String())
	}
	return args[len(args)-2]
}

// moduleRoot returns the root directory of the current Go module. Used
// by the build helpers above so the test runs from the module root
// regardless of which package's test is firing.
func moduleRoot() (string, error) {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	root := strings.TrimSpace(string(out))
	if root == "" {
		return "", errors.New("empty module root")
	}
	if runtime.GOOS == "windows" {
		root = strings.ReplaceAll(root, "\\", "/")
	}
	return root, nil
}
