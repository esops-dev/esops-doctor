// Package probes adapts the read-only capability surface of
// esops-go/pkg/client into data structures consumed by the rule engine.
//
// This package is the only one in the tree permitted to import
// esops-go/pkg/client. CI enforces that boundary.
//
// Two responsibilities:
//
//   - Known / IsKnown: the canonical set of probe names that rules may
//     reference. validate-rules consults this so an unregistered probe
//     fails at lint time rather than scan time.
//   - Registry: implements engine.ProbeRegistry by dispatching probe
//     names to per-capability adapters. The engine never sees a client.
package probes
