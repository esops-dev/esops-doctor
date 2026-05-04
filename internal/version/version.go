// Package version carries build-time identity. The defaults below are
// overridden via -ldflags at link time (see Makefile and .goreleaser.yaml).
package version

// Build-time identity, overridden via -ldflags at link time.
var (
	Version     = "dev"
	Commit      = "none"
	Date        = "unknown"
	EsopsModule = "unknown"
)
