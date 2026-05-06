package esopsdoctor

import "embed"

// Profiles is the embedded profile catalog, walked by internal/profiles
// at startup. Same module-root-embed reasoning as Catalog: //go:embed
// patterns can't reach above the directory containing the directive,
// and the operator-facing profiles/ tree lives at the repo root.
//
//go:embed profiles
var Profiles embed.FS
