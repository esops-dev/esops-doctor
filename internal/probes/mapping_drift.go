package probes

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"
)

// mappingDriftShape is one drift record: a live index whose top-level
// `dynamic` setting does not match the v2 composable template that
// claims its name. Cross-probe data — templates plus mappings — is
// joined client-side so a single rule can express the comparison with
// a flat-list comprehension.
//
// We only surface dynamic-setting drift today because it's the
// operator-actionable signal that doesn't require schema-aware diffs:
// "your template promises strict, your live index accepts anything"
// is unambiguous. Field-level drift (a field's type changed across
// rollovers, a new field appeared without a template change) needs a
// schema-diff layer that would dwarf the rule itself; deferred.
type mappingDriftShape struct {
	Index           string `json:"index"`
	Template        string `json:"template"`
	TemplateDynamic string `json:"template_dynamic"`
	IndexDynamic    string `json:"index_dynamic"`
}

// templateInfo is the per-template summary mapping_drift uses for the
// most-specific-pattern join. Kept package-private and small — the
// probe is the only consumer.
type templateInfo struct {
	name     string
	dynamic  string
	patterns []string
}

// fetchMappingDrift joins the v2 composable index templates with live
// index mappings and emits one entry per (template, live-index) pair
// where the top-level `dynamic` setting differs.
//
// Both reads happen sequentially in a single probe call rather than
// across two probes because rules over this data want to express the
// comparison as a single comprehension, not a cross-list join.
//
// Pairing rule: an index belongs to the template with the longest
// matching index_pattern (mirrors the cluster's most-specific-pattern
// resolution). When several templates tie, we pick the
// alphabetically-first name for determinism — the rule message would
// be misleading if the same index produced different findings across
// scans.
func fetchMappingDrift(ctx context.Context, mi client.MappingsInspector, it client.IndexTemplateInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tpls, err := it.GetTemplates(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("mapping_drift probe: %w", err)
	}
	mappings, err := mi.GetMappings(ctx, types.MappingFilter{
		Index:             "*",
		IgnoreUnavailable: true,
	})
	if err != nil {
		return nil, fmt.Errorf("mapping_drift probe: %w", err)
	}

	templates := make([]templateInfo, 0, len(tpls))
	for _, t := range tpls {
		templates = append(templates, templateInfo{
			name:     t.Name,
			dynamic:  templateDynamic(t),
			patterns: t.IndexPatterns,
		})
	}
	// Alphabetical pre-sort so ties on pattern-length break
	// deterministically — the rule message would be misleading if
	// the same index produced different findings across scans.
	sort.Slice(templates, func(i, j int) bool { return templates[i].name < templates[j].name })

	out := make([]mappingDriftShape, 0)
	for _, m := range mappings {
		if strings.HasPrefix(m.Name, ".") {
			// System / internal indices have schemas the cluster
			// owns; drop them so the rule does not flag indices the
			// operator did not author.
			continue
		}
		matched, ok := matchTemplate(m.Name, templates)
		if !ok {
			continue
		}
		if matched.dynamic == "" {
			// Template did not pin the dynamic setting — there is
			// nothing to drift from, only a default that the cluster
			// applies. Skip silently.
			continue
		}
		liveDynamic := m.Dynamic
		if liveDynamic == "" {
			// Cluster default is "true". Materialise it so the rule
			// can compare two non-empty strings.
			liveDynamic = "true"
		}
		if liveDynamic == matched.dynamic {
			continue
		}
		out = append(out, mappingDriftShape{
			Index:           m.Name,
			Template:        matched.name,
			TemplateDynamic: matched.dynamic,
			IndexDynamic:    liveDynamic,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return jsonShape("mapping_drift", out)
}

// templateDynamic pulls the top-level `dynamic` setting from a v2
// template's mappings block, if one is present. Returns "" when the
// template doesn't pin the field — the cluster default (which is
// "true") applies, and the drift rule treats absence as "no opinion".
func templateDynamic(t types.IndexTemplate) string {
	tmpl := t.Template
	if tmpl == nil {
		return ""
	}
	mappings, ok := tmpl["mappings"].(map[string]any)
	if !ok {
		return ""
	}
	switch d := mappings["dynamic"].(type) {
	case string:
		return d
	case bool:
		if d {
			return "true"
		}
		return "false"
	}
	return ""
}

// matchTemplate finds the most-specific (longest-pattern) template
// whose index_patterns match name. Ties on length break alphabetically
// because the caller pre-sorted by template name.
func matchTemplate(name string, templates []templateInfo) (templateInfo, bool) {
	var (
		best    templateInfo
		bestLen int
		seen    bool
	)
	for _, t := range templates {
		for _, p := range t.patterns {
			ok, err := path.Match(p, name)
			if err != nil || !ok {
				continue
			}
			if !seen || len(p) > bestLen {
				best = t
				bestLen = len(p)
				seen = true
			}
		}
	}
	return best, seen
}
