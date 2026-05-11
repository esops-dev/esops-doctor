package baseline

import (
	"sort"

	"github.com/esops-dev/esops-doctor/internal/findings"
)

// Diff is the result of comparing two scan reports. Each slice is
// sorted by Fingerprint.Key() so output is deterministic.
//
//   - Added: a finding present in new but not in old. New regressions
//     since the baseline scan — these are what a ratchet wants to
//     surface and gate on.
//   - Resolved: a finding present in old but not in new. Progress.
//   - SeverityChanged: a finding present in both, with a different
//     severity. SARIF-level collapse (critical → error) is filtered
//     out by Compare so a round-tripped SARIF baseline doesn't
//     report a phantom severity change.
type Diff struct {
	Added           []Entry
	Resolved        []Entry
	SeverityChanged []SeverityChange
}

// SeverityChange is the matched-pair view of a finding whose severity
// changed between the two reports. Old and New are the
// to/from severities; the fingerprint is on the Entry copies.
type SeverityChange struct {
	Old Entry
	New Entry
}

// Compare returns the set-difference of new against old.
func Compare(old, new *Set) Diff {
	var d Diff
	if old == nil && new == nil {
		return d
	}

	newKeys := map[string]Entry{}
	for _, e := range new.Entries() {
		newKeys[e.Fingerprint.Key()] = e
	}
	oldKeys := map[string]Entry{}
	for _, e := range old.Entries() {
		oldKeys[e.Fingerprint.Key()] = e
	}

	for k, e := range newKeys {
		ole, ok := oldKeys[k]
		if !ok {
			d.Added = append(d.Added, e)
			continue
		}
		if severityChanged(ole.Severity, e.Severity) {
			d.SeverityChanged = append(d.SeverityChanged, SeverityChange{Old: ole, New: e})
		}
	}
	for k, e := range oldKeys {
		if _, ok := newKeys[k]; !ok {
			d.Resolved = append(d.Resolved, e)
		}
	}
	sortEntries(d.Added)
	sortEntries(d.Resolved)
	sortChanges(d.SeverityChanged)
	return d
}

// severityChanged reports whether two severities differ in a way
// worth surfacing. The SARIF wire collapses critical to error on
// emit, so a baseline round-tripped through SARIF reads severities
// back as SeverityError where the original was SeverityCritical.
// Treat those two as equivalent: a real severity change crosses a
// SARIF-level boundary (note / warning / error), not a doctor-level
// boundary that SARIF can't represent.
func severityChanged(a, b findings.Severity) bool {
	if a == b {
		return false
	}
	if isSarifErrorLevel(a) && isSarifErrorLevel(b) {
		return false
	}
	// SeverityUnknown on either side typically means the baseline
	// row didn't carry an explicit severity. Treat that as
	// "no severity recorded" rather than as a change.
	if a == findings.SeverityUnknown || b == findings.SeverityUnknown {
		return false
	}
	return true
}

func isSarifErrorLevel(s findings.Severity) bool {
	return s == findings.SeverityError || s == findings.SeverityCritical
}

func sortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool {
		return es[i].Fingerprint.Key() < es[j].Fingerprint.Key()
	})
}

func sortChanges(cs []SeverityChange) {
	sort.Slice(cs, func(i, j int) bool {
		return cs[i].New.Fingerprint.Key() < cs[j].New.Fingerprint.Key()
	})
}

// Empty reports whether the diff has zero changes — neither
// regressions, resolutions, nor severity drift.
func (d Diff) Empty() bool {
	return len(d.Added) == 0 && len(d.Resolved) == 0 && len(d.SeverityChanged) == 0
}
