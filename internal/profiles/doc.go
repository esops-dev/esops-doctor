// Package profiles loads named profiles that apply severity overrides
// and rule selection to a rule catalog before evaluation. A profile is
// the "this catalog, scoped for this environment" knob — prod scans
// promote hygiene findings toward critical, dev scans demote them
// toward info, cis-bench narrows the catalog to the security and
// bootstrap-parity rules.
//
// Profiles are data, not code: a non-Go contributor adds a profile by
// dropping a YAML file into profiles/ at the repo root.
package profiles
