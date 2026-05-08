package probes

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"
)

// tierLayoutShape is a cross-probe rollup pairing the data-tier roles
// each node serves with the tier preference each non-system index
// asks for. Rules check whether an index's preferred tiers map to at
// least one node that actually serves them — the "logs index pinned
// to a tier no node has" failure mode.
//
// Built fresh per scan from /_cat/nodes (Node.Roles) and
// /<*>/_settings; sibling of the existing index_tier_preference_invalid
// rule (which only validates the preference string against the known
// tier list, with no cluster-side check).
type tierLayoutShape struct {
	Nodes   []tierLayoutNode  `json:"nodes"`
	Indices []tierLayoutIndex `json:"indices"`
}

type tierLayoutNode struct {
	Name  string   `json:"name"`
	Tiers []string `json:"tiers"`
	Roles []string `json:"roles"`
}

type tierLayoutIndex struct {
	Name           string   `json:"name"`
	PreferredTiers []string `json:"preferred_tiers"`
}

// fetchTierLayout combines the node-roster and per-index settings
// into the shape rules need. Errors propagate verbatim — neither
// upstream call carries a dialect-specific surface, so a probe-level
// failure indicates a real cluster problem.
//
// `data_*` roles map to tier names verbatim (`data_hot` → `data_hot`).
// Nodes with a generic `data` role (legacy / single-tier deployments)
// are surfaced with an empty Tiers list rather than synthesised
// memberships — the rule consumer then treats them as "any tier the
// preference asks for is unsatisfied", which is the right answer for
// a strict-tier-preference cluster and harmless for a single-tier
// cluster where no index has _tier_preference set.
func fetchTierLayout(ctx context.Context, ni client.NodeInspector, isi client.IndexSettingsInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	nodes, err := ni.Nodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("tier_layout probe: %w", err)
	}
	settings, err := isi.GetSettings(ctx, types.IndexSettingsGetRequest{
		Indices:           []string{"*"},
		IgnoreUnavailable: true,
	})
	if err != nil {
		return nil, fmt.Errorf("tier_layout probe: %w", err)
	}

	out := tierLayoutShape{
		Nodes:   make([]tierLayoutNode, 0, len(nodes)),
		Indices: make([]tierLayoutIndex, 0, len(settings)),
	}
	for _, n := range nodes {
		row := tierLayoutNode{
			Name:  n.Name,
			Roles: append([]string(nil), n.Roles...),
			Tiers: extractTierRoles(n.Roles),
		}
		out.Nodes = append(out.Nodes, row)
	}
	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].Name < out.Nodes[j].Name })

	for _, s := range settings {
		row := tierLayoutIndex{Name: s.Index}
		row.PreferredTiers = extractTierPreference(s.Settings)
		out.Indices = append(out.Indices, row)
	}
	sort.Slice(out.Indices, func(i, j int) bool { return out.Indices[i].Name < out.Indices[j].Name })

	return jsonShape("tier_layout", out)
}

// extractTierRoles filters the node's role list down to the data-tier
// entries and returns them in declaration order (the cluster's own
// /_cat/nodes order is the most useful for reporting).
func extractTierRoles(roles []string) []string {
	if len(roles) == 0 {
		return nil
	}
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		if strings.HasPrefix(r, "data_") {
			out = append(out, r)
		}
	}
	return out
}

// extractTierPreference walks the index settings tree for
// `index.routing.allocation.include._tier_preference` and returns the
// comma-separated value as a slice. Whitespace is trimmed and empty
// segments are dropped. Both the nested ({"index":{"routing":{...}}})
// and flat ("index.routing.allocation.include._tier_preference") shapes
// are accepted because this probe doesn't know which one the cluster
// returned — IndexSettingsInspector defaults to nested but a future
// caller may switch to flat.
func extractTierPreference(settings map[string]any) []string {
	if v, ok := settings["index.routing.allocation.include._tier_preference"]; ok {
		return splitTierList(v)
	}
	idx, ok := mapAt(settings, "index")
	if !ok {
		return nil
	}
	routing, ok := mapAt(idx, "routing")
	if !ok {
		return nil
	}
	alloc, ok := mapAt(routing, "allocation")
	if !ok {
		return nil
	}
	include, ok := mapAt(alloc, "include")
	if !ok {
		return nil
	}
	if v, ok := include["_tier_preference"]; ok {
		return splitTierList(v)
	}
	return nil
}

func mapAt(parent map[string]any, key string) (map[string]any, bool) {
	v, ok := parent[key]
	if !ok {
		return nil, false
	}
	m, ok := v.(map[string]any)
	return m, ok
}

func splitTierList(v any) []string {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
