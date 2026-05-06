# Probe reference

A probe is a thin read-only adapter over one capability of `esops-go/pkg/client`. Every rule names exactly one probe in its `probe:` field; the engine fetches the probe's data once per scan and binds it to `self` in the rule's CEL.

This document lists every registered probe, what it returns, and a short example condition. For the authoring workflow, see [rules.md](rules.md).

## Self shape conventions

- **List probes** return a YAML/JSON array. `self` is `[]any`; iterate
  with `self.all(x, …)`, `self.exists(x, …)`, or
  `self.filter(x, …)`. `size(self) == 0` is the empty-cluster pass.
- **Object probes** return a single mapping. `self` is
  `map[string]any`; index fields directly: `self.status == 'green'`.
  Empty-cluster passes need explicit field guards (`!has(self.x)`)
  rather than a length check.

Numeric fields decode as `float64` after the JSON round-trip — convert with `int(...)` before comparing with int literals. Optional fields (`omitempty` upstream) need `has(...)` guards before access.

## Dialect notes

- `ilm_state` is Elasticsearch-only. On OpenSearch the engine reports
  the rule as Skipped with reason "ILM is Elasticsearch-only".
- `ism_state` is the OpenSearch counterpart, Skipped on Elasticsearch.
- `deprecation_log` is Elasticsearch-only.

A rule's `dialects:` field gates evaluation up-front, before the probe is even called. The dialect-specific Skipped reason above only fires when a rule lists both dialects but the cluster's adapter cannot serve the data.

---

## nodes

`/_cat/nodes` — one row per cluster node. List of objects.

| Field | Type | Notes |
|---|---|---|
| `name` | string | Node name |
| `roles` | []string | e.g. `["master", "data", "ingest"]` |
| `is_data_node` | bool |  |
| `version` | string | e.g. `"9.0.0"` |
| `ip` | string |  |
| `master` | bool | True for current cluster master |
| `heap_used_bytes` | int |  |
| `heap_max_bytes` | int | Configured -Xmx |
| `heap_percent` | int |  |
| `disk_used_bytes` | int |  |
| `disk_avail_bytes` | int |  |
| `disk_total_bytes` | int |  |
| `disk_used_percent` | int |  |
| `cpu_percent` | int |  |
| `load_1m` | string |  |
| `uptime` | string |  |

```cel
# Every node should run a non-EOL major version
self.all(n, has(n.version) && n.version.startsWith('9.'))
```

## node_stats

`/_nodes/jvm` + `/_nodes/stats/os` — heap configuration plus host RAM. List of objects. The narrower view that `nodes` doesn't carry: `Xms` init, total physical memory.

| Field | Type | Notes |
|---|---|---|
| `name` | string |  |
| `jvm.heap.init_bytes` | int | -Xms |
| `jvm.heap.max_bytes` | int | -Xmx |
| `os.total_physical_memory_bytes` | int | Host RAM |

```cel
self.all(n, !has(n.jvm.heap.max_bytes) ||
            int(n.jvm.heap.max_bytes) <= 31 * 1024 * 1024 * 1024)
```

## node_bootstrap

`/_nodes/jvm` + `/_nodes/process` — bootstrap-check posture. List of objects.

| Field | Type | Notes |
|---|---|---|
| `name` | string |  |
| `mlockall_enabled` | bool | `bootstrap.memory_lock` outcome |
| `max_file_descriptors` | int | Process FD limit |
| `max_map_count` | int | OS `vm.max_map_count`, when surfaced |
| `bootstrap_warnings` | []string | Cluster's own warning text, verbatim |

```cel
self.all(n, !has(n.mlockall_enabled) || n.mlockall_enabled == true)
```

## cluster_health

`/_cluster/health`. **Single object.**

| Field | Type | Notes |
|---|---|---|
| `cluster_name` | string |  |
| `status` | string | `green` / `yellow` / `red` |
| `timed_out` | bool |  |
| `number_of_nodes` | int |  |
| `number_of_data_nodes` | int |  |
| `active_primary_shards` | int |  |
| `active_shards` | int |  |
| `relocating_shards` | int |  |
| `initializing_shards` | int |  |
| `unassigned_shards` | int |  |
| `delayed_unassigned_shards` | int |  |
| `number_of_pending_tasks` | int |  |
| `number_of_in_flight_fetch` | int |  |
| `task_max_waiting_in_queue_millis` | int |  |
| `active_shards_percent_as_number` | float |  |

```cel
has(self.status) && self.status == 'green'
```

## cluster_settings

`/_cluster/settings` — the **narrow** view (drain/uncordon-shaped): the `cluster.routing.allocation.exclude._name` field only. Single object. **Note: fields here use Go-style PascalCase** (no JSON tags upstream); prefer `cluster_settings_full` for new rules.

| Field | Type |
|---|---|
| `PersistentExcludeName` | []string |
| `TransientExcludeName` | []string |

## cluster_settings_full

`/_cluster/settings?flat_settings=true` — the full envelope. **Single
object** with three flat-keyed maps.

| Field | Type | Notes |
|---|---|---|
| `persistent` | map[string]any | Operator-set persistent settings |
| `transient` | map[string]any | Operator-set transient settings |
| `defaults` | map[string]any | Empty unless `include_defaults` was on |

Values are typically strings (`"true"`, `"5000"`) — convert at the leaf. Use `'key' in map`, not `has(map['key'])`.

```cel
'action.destructive_requires_name' in self.persistent &&
string(self.persistent['action.destructive_requires_name']) == 'true'
```

## indices

`/_cat/indices` — one row per index. List of objects.

| Field | Type | Notes |
|---|---|---|
| `name` | string |  |
| `uuid` | string |  |
| `health` | string | `green` / `yellow` / `red` |
| `status` | string | `open` / `close` |
| `primaries` | int | Primary shard count |
| `replicas` | int | Replica count per primary |
| `docs_count` | int |  |
| `docs_deleted` | int |  |
| `store_bytes` | int | Total across primary + replicas |
| `primary_store_bytes` | int | Primary-only |
| `creation_date_millis` | int |  |

System indices are dot-prefixed (`.ds-*`, `.security-*`); the standard exclusion is `!idx.name.startsWith('.')`.

## index_settings

`GET /*/_settings` — per-index settings tree. List of objects.

| Field | Type | Notes |
|---|---|---|
| `index` | string |  |
| `settings` | map[string]any | Cluster's nested settings tree |
| `defaults` | map[string]any | Empty unless `include_defaults` on |

Settings are nested by default (the probe does not set `flat_settings=true`). String values are typical for numeric and boolean settings; `int(...)` / `string(...)` to compare.

```cel
self.all(idx, !has(idx.settings.index.mapping.total_fields.limit) ||
              int(idx.settings.index.mapping.total_fields.limit) <= 5000)
```

## index_templates

`GET /_index_template` — composable (v2) templates. List of objects.

| Field | Type | Notes |
|---|---|---|
| `name` | string |  |
| `index_patterns` | []string |  |
| `priority` | int | Defaults to 0 when unset |
| `version` | int |  |
| `composed_of` | []string | Component templates |
| `template` | map[string]any | Inner `{settings, mappings, aliases}` |
| `data_stream` | map[string]any | Set only on data-stream templates |

```cel
self.all(t, has(t.priority) && int(t.priority) > 0)
```

## mappings

`GET /*/_mapping` — per-index mapping trees. List of objects.

| Field | Type | Notes |
|---|---|---|
| `name` | string | Index name |
| `properties` | map[string]any | Cluster's nested `properties` tree |
| `meta` | map[string]any | User-defined `_meta` |
| `dynamic` | string | `"true"` / `"false"` / `"strict"` / `"runtime"` (omitted when unset — defaults to true) |

`properties` is the cluster's raw mapping tree. Each value is a property descriptor with optional `type`, `properties` (for nested objects), `analyzer`, etc. CEL has no recursion, so depth checks are written as fixed-depth nested `exists`:

```cel
# At least four levels of nested objects beneath the root
self.all(idx, !has(idx.properties) || !idx.properties.exists(a,
  has(idx.properties[a].properties) &&
  idx.properties[a].properties.exists(b,
    has(idx.properties[a].properties[b].properties))))
```

## aliases

`/_cat/aliases` — one row per alias→index binding. List of objects.

| Field | Type | Notes |
|---|---|---|
| `alias` | string |  |
| `index` | string | One row per index when an alias fronts N |
| `filter` | string |  |
| `routing_index` | string |  |
| `routing_search` | string |  |
| `is_write_index` | bool |  |

## allocation

`/_cat/allocation` — per-node shard count and disk breakdown. List of objects. Includes a special `name == "UNASSIGNED"` pseudo-row for shards waiting to be placed.

| Field | Type | Notes |
|---|---|---|
| `name` | string | Node name, or `"UNASSIGNED"` |
| `shards` | int | Per-node shard count |
| `disk_indices_bytes` | int |  |
| `disk_used_bytes` | int |  |
| `disk_avail_bytes` | int |  |
| `disk_total_bytes` | int |  |
| `disk_percent` | int |  |
| `host` | string |  |
| `ip` | string |  |

```cel
self.all(n, !has(n.name) || n.name == 'UNASSIGNED' ||
            !has(n.shards) || int(n.shards) <= 600)
```

## snapshots

Aggregated `/_snapshot/*/*` across every registered repository. List of objects.

| Field | Type | Notes |
|---|---|---|
| `repository` | string |  |
| `name` | string |  |
| `uuid` | string |  |
| `state` | string | `SUCCESS` / `IN_PROGRESS` / `FAILED` / `PARTIAL` / `INCOMPATIBLE` |
| `indices` | []string | Indices captured |
| `include_global_state` | bool |  |
| `start_time_millis` | int |  |
| `end_time_millis` | int |  |
| `duration_millis` | int |  |
| `shards_total` | int |  |
| `shards_successful` | int |  |
| `shards_failed` | int |  |
| `version` | string |  |
| `failures` | []object | Cluster's per-shard failure details, raw |

## snapshot_repositories

`GET /_snapshot` — registered repositories. List of objects.

| Field | Type | Notes |
|---|---|---|
| `name` | string |  |
| `type` | string | `fs` / `s3` / `gcs` / `azure` / … |
| `settings` | map[string]any | Type-specific config (bucket, base_path, …) |

## ilm_state

`/_ilm/policy` — ILM policies. **Elasticsearch only.** List of objects.

| Field | Type | Notes |
|---|---|---|
| `name` | string |  |
| `version` | int |  |
| `modified_date` | string | RFC3339 |
| `in_use_by.indices` | []string |  |
| `in_use_by.data_streams` | []string |  |
| `in_use_by.composable_templates` | []string |  |
| `definition` | map[string]any | Policy phases tree |

## ism_state

`/_plugins/_ism/policies` — ISM policies. **OpenSearch only.** List of objects.

| Field | Type | Notes |
|---|---|---|
| `id` | string |  |
| `seq_no` | int |  |
| `primary_term` | int |  |
| `definition` | map[string]any | States/transitions tree |

## security_audit

`/_security/*` (ES) or `/_plugins/_security/api/*` (OS) — full audit. 

**Single object.**

| Field | Type | Notes |
|---|---|---|
| `tls.scheme` | string | `http` / `https` (client-side) |
| `tls.insecure_skip_verify` | bool | Client-side `insecure: true` |
| `tls.cacert_set` | bool |  |
| `tls.auth_type` | string | `basic` / `apikey` / `none` / … |
| `tls.client_cert_set` | bool |  |
| `tls.transport_tls_enabled` | bool | Cluster-side, when surfaced |
| `tls.transport_tls_verified` | bool |  |
| `status.dialect` | string |  |
| `status.enabled` | bool | Whole security model on/off |
| `status.note` | string | Short reason when disabled |
| `status.notes` | []string | Per-collection partial failures (e.g. "api_keys: forbidden") |
| `users[]` | list | See below |
| `roles[]` | list | See below |
| `role_mappings[]` | list |  |
| `api_keys[]` | list | ES only — empty on OS |
| `tenants[]` | list | OS only — empty on ES |

`users[]` entry:

| Field | Type | Notes |
|---|---|---|
| `username` | string |  |
| `enabled` | bool |  |
| `reserved` | bool | True for built-in accounts |
| `roles` | []string |  |
| `backend_roles` | []string | OS-only |
| `full_name` | string |  |
| `email` | string |  |
| `password_changed_at` | string | RFC3339, when surfaced. Empty on OS and on older ES versions. |

`roles[]` entry:

| Field | Type | Notes |
|---|---|---|
| `name` | string |  |
| `reserved` | bool |  |
| `cluster_privileges` | []string | e.g. `["all", "monitor"]` |
| `index_patterns` | []string | Union across the role's index entries |
| `description` | string |  |

`api_keys[]` entry (ES):

| Field | Type | Notes |
|---|---|---|
| `id` | string |  |
| `name` | string |  |
| `username` | string |  |
| `realm` | string |  |
| `invalidated` | bool |  |
| `creation` | string | RFC3339 |
| `expiration` | string | Empty when no expiry was set |

## transport_tls

`/_nodes/settings` — cluster-side transport TLS posture. **Single object.** Aggregated across reachable nodes; `enabled` is true only when **every** node reports transport TLS on.

| Field | Type | Notes |
|---|---|---|
| `transport_tls_enabled` | bool |  |
| `transport_tls_verified` | bool | Verification mode (ES) / hostname enforcement (OS) |

## recovery

`GET /_all/_recovery?active_only=true` — only shards still relocating or recovering. **Single object.**

| Field | Type | Notes |
|---|---|---|
| `indices` | []object | One per index with active recovery |
| `all_done` | bool | Derived; true iff every shard reached DONE |

`indices[]` entry:

| Field | Type |
|---|---|
| `index` | string |
| `shards` | []object |

`shards[]` entry:

| Field | Type | Notes |
|---|---|---|
| `id` | int |  |
| `type` | string | `STORE` / `SNAPSHOT` / `PEER` / `EMPTY_STORE` |
| `stage` | string | `INIT` / `INDEX` / `TRANSLOG` / `FINALIZE` / `DONE` |
| `primary` | bool |  |
| `source` | string | `repo:snapshot:index` for SNAPSHOT recoveries |
| `bytes_percent` | string | Human-rendered, e.g. `"42.0%"` |
| `files_percent` | string |  |
| `bytes_total` | int |  |
| `bytes_recovered` | int |  |
| `files_total` | int |  |
| `files_recovered` | int |  |

## pending_tasks

`/_cluster/pending_tasks` — master-side cluster-state queue. List of objects.

| Field | Type | Notes |
|---|---|---|
| `insert_order` | int |  |
| `priority` | string | `URGENT` / `HIGH` / `NORMAL` / `LOW` |
| `source` | string | What enqueued the task (e.g. `shard-failed`, `put-mapping`) |
| `time_in_queue_millis` | int |  |
| `executing` | bool |  |

## deprecation_log

`/_migration/deprecations` — flat list across the cluster's per-category buckets. **Elasticsearch only.** List of objects.

| Field | Type | Notes |
|---|---|---|
| `category` | string | `cluster_settings`, `node_settings`, `index_settings`, `ml_settings`, `data_streams`, `templates`, `ilm_policies` |
| `target` | string | Index name for `index_settings`, etc. |
| `level` | string | `critical` / `warning` / `info` / `none` |
| `message` | string |  |
| `url` | string | Long-form remediation docs |
| `details` | string | Cluster-supplied extra context |
| `resolve_during_rolling_upgrade` | bool |  |
| `meta` | string | Free-form `_meta` block, JSON-encoded |

```cel
self.all(d, !has(d.level) || d.level != 'critical')
```

---

## Adding a probe

Adding a probe requires a Go change. The shape:

1. Add a constant + entry in `internal/probes/probes.go` (`Known()`
   set + dispatch arm).
2. Drop a `internal/probes/<name>.go` adapter with a
   `fetch<Name>(ctx, capability)` function that calls the upstream
   capability and returns `jsonShape("<name>", result)`.
3. Wire a fake into `dispatch_test.go`'s `fullClient()` and add the
   capability to the `*client.Client` literal.
4. Run `go test ./internal/probes/...` — the dispatch sweep test will
   catch a missing arm.
