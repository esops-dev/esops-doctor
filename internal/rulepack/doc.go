// Package rulepack implements the supply-chain-hardened rule-pack
// convention: a directory or archive of rule YAMLs accompanied by a
// MANIFEST.yaml whose SHA-256 hashes are verified at load time.
//
// The MANIFEST.yaml itself is intended to be cosign-signed by the pack
// author and verified by the operator BEFORE pointing doctor at the
// pack. Doctor never invokes cosign — adding the sigstore SDK would
// blow the dependency budget documented in CLAUDE.md §4 — but the
// hash check makes the pack tamper-evident once the manifest's
// signature has been verified.
//
// See docs/rules-packs.md for the operator workflow.
package rulepack
