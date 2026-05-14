package esopsdoctor

import "embed"

// Schemas are the JSON Schema documents for the rule, profile, and
// waiver YAML files doctor consumes. Editors that recognise YAML
// language servers (vscode-yaml, helix, neovim's yamlls) load these to
// surface validation errors as the operator types — see
// `esops-doctor docs schemas` to write them to disk, or fetch them
// from the release archive.
//
//go:embed schemas
var Schemas embed.FS
