package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	yaml "go.yaml.in/yaml/v3"

	"github.com/esops-dev/esops-doctor/internal/rules"
)

// coverageBucket is one in-scope area of the doctor's design scope.
// Rules name the bucket via membership in Members (rule IDs); the
// catalog-coverage view counts how many of a bucket's named rules are
// in the current catalog and reports the rest as gaps.
//
// The bucket list is the design scope's own enumeration of what the
// doctor's catalog should cover. Adding a new rule that fills a
// previously-empty bucket means listing it here so the next
// `list-rules --coverage` run reports the gap closed; adding a rule
// with no obvious bucket home means widening the design scope first
// or extending the catalog in a direction the design says we don't go.
type coverageBucket struct {
	ID          string
	Description string
	Members     []string
}

// coverageBuckets is the canonical design-scope expansion. Order is
// significant: the report renders buckets in the order the design
// scope enumerates them (resource sanity, mappings, lifecycle,
// security, hygiene, bootstrap parity, destructive-op safeguards,
// anti-pattern defaults, adjacent additions). Within each bucket
// Members lists the rule IDs that satisfy the bucket; an unrecognised
// ID is reported by validateCoverageBuckets so the catalog and the
// bucket list cannot drift silently.
var coverageBuckets = []coverageBucket{
	{
		ID:          "resource_sanity",
		Description: "Heap, mlockall, shard count, disk watermarks, zone awareness, dedicated masters, JVM ergonomics, mmap, circuit breakers",
		Members: []string{
			"heap_size",
			"bootstrap_memory_lock",
			"shard_count_per_node",
			"shard_size_distribution",
			"disk_watermarks",
			"zone_awareness",
			"dedicated_master_nodes",
			"jvm_gc_ergonomics",
			"node_store_allow_mmap",
			"circuit_breaker_limits",
			"search_default_limits",
			"index_max_result_window_high",
		},
	},
	{
		ID:          "mappings",
		Description: "Dynamic mapping, unbounded keyword cardinality, deeply nested objects, missing index templates, deprecated field types, mapping drift",
		Members: []string{
			"dynamic_mapping_strict",
			"unbounded_keyword_cardinality",
			"deeply_nested_objects",
			"catchall_index_template",
			"composable_template_priority",
			"template_no_index_patterns",
			"deprecated_field_types",
			"mapping_template_drift",
		},
	},
	{
		ID:          "lifecycle",
		Description: "ILM/ISM presence, snapshot policy + recent successful execution, repository configured, untested restore, retention gaps, pending tasks",
		Members: []string{
			"ilm_policy_present",
			"ism_policy_present",
			"snapshot_repository_configured",
			"snapshot_failed_state",
			"snapshot_partial_state",
			"snapshot_slo_age",
			"untested_restore",
			"retention_gap",
			"pending_task_accumulation",
			"ccr_follower_unhealthy",
			"ccr_auto_follow_paused",
			"ccr_lease_expiring",
		},
	},
	{
		ID:          "security",
		Description: "Anonymous access, TLS, default credentials, audit logging, permissive roles, stale API keys / service tokens, deprecated realms, node-to-node encryption, recent audit warnings, licence",
		Members: []string{
			"anonymous_access",
			"tls_transport",
			"tls_insecure_skip_verify",
			"http_tls",
			"node_to_node_encryption",
			"default_credentials",
			"audit_logging_enabled",
			"recent_audit_warnings",
			"permissive_superuser_role",
			"api_keys_no_expiration",
			"stale_api_keys",
			"stale_service_tokens",
			"deprecated_realms",
			"security_disabled",
			"license_expiration",
		},
	},
	{
		ID:          "hygiene",
		Description: "Cluster-settings drift, version skew, deprecation logs, pending tasks, cluster health",
		Members: []string{
			"cluster_health_status",
			"version_skew",
			"deprecation_log_critical",
			"deprecation_log_warning",
			"transient_settings_drift",
			"unassigned_shards",
			"delayed_unassigned_shards",
			"remote_cluster_unreachable",
		},
	},
	{
		ID:          "bootstrap",
		Description: "Bootstrap-check parity (FDs, mlockall, etc.)",
		Members: []string{
			"bootstrap_check_warnings",
			"max_file_descriptors_low",
			"bootstrap_memory_lock",
		},
	},
	{
		ID:          "destructive_ops",
		Description: "action.destructive_requires_name, total_fields.limit, script.allowed_types, replica-less indices",
		Members: []string{
			"destructive_requires_name",
			"mapping_total_fields_limit_high",
			"script_limits",
			"index_no_replicas",
		},
	},
	{
		ID:          "anti_pattern_defaults",
		Description: "Default cluster name, network.host wildcard, suspect discovery settings",
		Members: []string{
			"default_cluster_name",
			"network_host_wildcard",
			"suspect_discovery_settings",
		},
	},
	{
		ID:          "adjacent_additions",
		Description: "Cross-cluster replication / search readiness, hot/warm/cold tier sanity",
		Members: []string{
			"remote_cluster_unreachable",
			"ccr_follower_unhealthy",
			"ccr_auto_follow_paused",
			"ccr_lease_expiring",
			"index_tier_preference_invalid",
			"index_tier_no_eligible_node",
			"index_legacy_box_routing",
		},
	},
}

// coverageEntry is the per-bucket entry rendered into json/yaml output.
// Present and Missing are exported so a downstream consumer (CI gate,
// dashboard) can walk them without parsing the human-friendly summary.
type coverageEntry struct {
	Bucket      string   `json:"bucket" yaml:"bucket"`
	Description string   `json:"description" yaml:"description"`
	Total       int      `json:"total" yaml:"total"`
	Covered     int      `json:"covered" yaml:"covered"`
	Present     []string `json:"present" yaml:"present"`
	Missing     []string `json:"missing,omitempty" yaml:"missing,omitempty"`
}

// coverageDoc is the top-level doc for --coverage --output json|yaml.
// SchemaVersion mirrors the rule-list document so the format is
// scriptable on the same terms.
type coverageDoc struct {
	SchemaVersion int             `json:"schema_version" yaml:"schema_version"`
	Buckets       []coverageEntry `json:"buckets" yaml:"buckets"`
	Unbucketed    []string        `json:"unbucketed,omitempty" yaml:"unbucketed,omitempty"`
}

// computeCoverage collapses the catalog into the design-scope bucket
// view. Every catalog rule is matched against the bucket list; rules
// that don't appear in any bucket land in Unbucketed so a maintainer
// notices the gap without trawling the catalog by hand.
func computeCoverage(rs []rules.Rule) coverageDoc {
	have := make(map[string]struct{}, len(rs))
	for _, r := range rs {
		have[r.ID] = struct{}{}
	}

	bucketed := make(map[string]struct{})
	out := coverageDoc{SchemaVersion: 1}
	for _, b := range coverageBuckets {
		entry := coverageEntry{
			Bucket:      b.ID,
			Description: b.Description,
			Total:       len(b.Members),
		}
		for _, id := range b.Members {
			bucketed[id] = struct{}{}
			if _, ok := have[id]; ok {
				entry.Covered++
				entry.Present = append(entry.Present, id)
			} else {
				entry.Missing = append(entry.Missing, id)
			}
		}
		sort.Strings(entry.Present)
		sort.Strings(entry.Missing)
		out.Buckets = append(out.Buckets, entry)
	}

	for _, r := range rs {
		if _, ok := bucketed[r.ID]; !ok {
			out.Unbucketed = append(out.Unbucketed, r.ID)
		}
	}
	sort.Strings(out.Unbucketed)
	return out
}

// renderCoverageTable emits one row per bucket: id, covered/total,
// missing IDs (if any). The summary footer prints catalog-wide totals
// plus any unbucketed rules so a maintainer reading the output sees
// both ends of the drift in one pass.
func renderCoverageTable(w io.Writer, doc coverageDoc) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "BUCKET\tCOVERED\tMISSING"); err != nil {
		return err
	}
	totalRules, coveredRules := 0, 0
	for _, b := range doc.Buckets {
		totalRules += b.Total
		coveredRules += b.Covered
		missing := strings.Join(b.Missing, ", ")
		if missing == "" {
			missing = "-"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%d/%d\t%s\n", b.Bucket, b.Covered, b.Total, missing); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\n%d/%d bucket members covered across %d bucket(s)\n",
		coveredRules, totalRules, len(doc.Buckets)); err != nil {
		return err
	}
	if len(doc.Unbucketed) > 0 {
		_, err := fmt.Fprintf(w, "%d rule(s) not assigned to any bucket: %s\n",
			len(doc.Unbucketed), strings.Join(doc.Unbucketed, ", "))
		return err
	}
	return nil
}

func renderCoverageJSON(w io.Writer, doc coverageDoc) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func renderCoverageYAML(w io.Writer, doc coverageDoc) error {
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	defer func() { _ = enc.Close() }()
	return enc.Encode(doc)
}
