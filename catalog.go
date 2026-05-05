// Package esopsdoctor exposes module-level resources that need to live
// at the module root for Go's //go:embed directive — patterns can't
// reference parent directories. The repo-root rules/ tree is operator-
// facing (contributors browsing the repo see the rule files first
// thing), so the loader at internal/rules/ reaches it through this
// embed.FS rather than relocating the data.
package esopsdoctor

import "embed"

// Catalog is the embedded rule catalog, walked by internal/rules at
// startup. Dotfile placeholders (.gitkeep in empty category dirs) are
// excluded by Go's default embed behaviour; the loader filters by
// .yaml suffix as a second guard.
//
//go:embed rules
var Catalog embed.FS
