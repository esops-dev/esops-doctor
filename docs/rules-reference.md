# Rule reference

Generated from the embedded catalog by `esops-doctor docs rules`. Do not edit by hand — change the rule YAML and regenerate.

Total rules: **67**.

## Table of contents

- [bootstrap](#bootstrap) — 3 rule(s)
- [destructive_ops](#destructive-ops) — 3 rule(s)
- [hygiene](#hygiene) — 10 rule(s)
- [lifecycle](#lifecycle) — 11 rule(s)
- [mappings](#mappings) — 8 rule(s)
- [resource_sanity](#resource-sanity) — 16 rule(s)
- [security](#security) — 16 rule(s)

## bootstrap

### `bootstrap_check_warnings`

**Cluster reports bootstrap-check warnings**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | medium | prod, bootstrap, framework:cis |

The cluster's own bootstrap-check machinery surfaces per-node warnings (max_map_count, mmapfs limits, vm.swappiness, system call filter availability, etc.). Each entry is a check the cluster ran and decided was misconfigured. Surface the count so an operator pulls the per-warning text from `--output json` and addresses each one.

- **Probe:** `node_bootstrap`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(n,
  !has(n.bootstrap_warnings) || size(n.bootstrap_warnings) == 0
)
```

**Count expression (CEL):**

```cel
size(self.filter(n,
  has(n.bootstrap_warnings) && size(n.bootstrap_warnings) > 0
))
```

**Message template:** {{count}} node(s) reporting bootstrap-check warnings.

**Remediation:**

- Command: Inspect the per-node bootstrap_warnings list (esops-doctor scan --output json | jq) and resolve each warning per the cluster's own reference
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/bootstrap-checks.html>
- `esops ops nodes`

---

### `bootstrap_memory_lock`

**bootstrap.memory_lock not enabled**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch, opensearch | low | prod, performance, bootstrap, framework:cis |

Without bootstrap.memory_lock the JVM heap can be paged out to disk under memory pressure — page-in latency on a hot node turns into a multi-second GC stall. The official guidance is to either mlockall the JVM or disable swap entirely. Flag any node the cluster reports as not memory-locked.

- **Probe:** `node_bootstrap`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(n,
  !has(n.mlockall_enabled) || n.mlockall_enabled == true
)
```

**Count expression (CEL):**

```cel
size(self.filter(n,
  has(n.mlockall_enabled) && n.mlockall_enabled == false
))
```

**Message template:** {{count}} node(s) not running with bootstrap.memory_lock enabled.

**Remediation:**

- Command: Set bootstrap.memory_lock=true in elasticsearch.yml/opensearch.yml and ensure the service unit raises LimitMEMLOCK=infinity
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/setup-configuration-memory.html>
- `esops ops nodes`

---

### `max_file_descriptors_low`

**Process file-descriptor limit below recommendation**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch, opensearch | low | prod, bootstrap, framework:cis |

Elasticsearch and OpenSearch both recommend a minimum of 65535 file descriptors per process. A node with a lower ulimit will hit "Too many open files" failures under shard recovery or heavy indexing. Flag any node where process.max_file_descriptors sits below the documented floor.

- **Probe:** `node_bootstrap`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(n,
  !has(n.max_file_descriptors) || int(n.max_file_descriptors) >= 65535
)
```

**Count expression (CEL):**

```cel
size(self.filter(n,
  has(n.max_file_descriptors) && int(n.max_file_descriptors) < 65535
))
```

**Message template:** {{count}} node(s) with max_file_descriptors below the 65535 minimum.

**Remediation:**

- Command: Raise the process file-descriptor ulimit (LimitNOFILE=65535 in the systemd unit, or /etc/security/limits.conf for non-systemd hosts) and restart the node
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/setting-system-settings.html>
- `esops ops nodes`

---

## destructive_ops

### `destructive_requires_name`

**action.destructive_requires_name not enforced**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch, opensearch | low | prod, destructive_ops, framework:cis |

With action.destructive_requires_name=true the cluster refuses bulk-destructive APIs (DELETE _all, DELETE *) that would otherwise let a typo wipe every index. ES 8+ defaults to true; ES 7 and OpenSearch default to false. Flag any cluster where the setting is not explicitly "true" so the operator's safety knob is on the record rather than relying on a version-dependent default.

- **Probe:** `cluster_settings_full`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
(has(self.persistent) &&
 'action.destructive_requires_name' in self.persistent &&
 string(self.persistent['action.destructive_requires_name']) == 'true') ||
(has(self.transient) &&
 'action.destructive_requires_name' in self.transient &&
 string(self.transient['action.destructive_requires_name']) == 'true')
```

**Count expression (CEL):**

```cel
((has(self.persistent) &&
  'action.destructive_requires_name' in self.persistent &&
  string(self.persistent['action.destructive_requires_name']) == 'true') ||
 (has(self.transient) &&
  'action.destructive_requires_name' in self.transient &&
  string(self.transient['action.destructive_requires_name']) == 'true')) ? 0 : 1
```

**Message template:** action.destructive_requires_name is not set to "true".

**Remediation:**

- Command: Set persistent action.destructive_requires_name to true via PUT /_cluster/settings
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-update-settings.html>
- `esops ops settings get`
- `esops ops settings set`

---

### `index_no_replicas`

**User index running with zero replicas**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | low | prod, availability |

An index with index.number_of_replicas = 0 has no redundancy — a single shard loss equals data loss. Common in dev/CI but a foot-gun in production. System indices (dot-prefixed) are excluded since their replica policy is the cluster's call; data-stream backing indices are excluded too.

- **Probe:** `index_settings`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(idx,
  !has(idx.index) ||
  idx.index.startsWith('.') ||
  !has(idx.settings) ||
  !has(idx.settings.index) ||
  !has(idx.settings.index.number_of_replicas) ||
  int(idx.settings.index.number_of_replicas) > 0
)
```

**Count expression (CEL):**

```cel
size(self.filter(idx,
  has(idx.index) &&
  !idx.index.startsWith('.') &&
  has(idx.settings) &&
  has(idx.settings.index) &&
  has(idx.settings.index.number_of_replicas) &&
  int(idx.settings.index.number_of_replicas) == 0
))
```

**Message template:** {{count}} non-system index/indices with zero replicas configured.

**Remediation:**

- Command: Set index.number_of_replicas to at least 1 on the affected indices, or apply a template that does so for future indices
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/index-modules.html#dynamic-index-settings>
- `esops index list`
- `esops index settings`
- `esops index template`

---

### `mapping_total_fields_limit_high`

**Index raises total_fields.limit far above default**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | medium | destructive_ops, mappings |

Default index.mapping.total_fields.limit is 1000 — a deliberate ceiling against unbounded field explosions from dynamic mappings. An index that bumps it past 5000 is either modelling a genuinely-wide schema or papering over an upstream producer sending unbounded keys. Either way the cluster is on the hook for the heap cost; surface the override so the trade-off is explicit.

- **Probe:** `index_settings`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(idx,
  !has(idx.settings) ||
  !has(idx.settings.index) ||
  !has(idx.settings.index.mapping) ||
  !has(idx.settings.index.mapping.total_fields) ||
  !has(idx.settings.index.mapping.total_fields.limit) ||
  int(idx.settings.index.mapping.total_fields.limit) <= 5000
)
```

**Count expression (CEL):**

```cel
size(self.filter(idx,
  has(idx.settings) &&
  has(idx.settings.index) &&
  has(idx.settings.index.mapping) &&
  has(idx.settings.index.mapping.total_fields) &&
  has(idx.settings.index.mapping.total_fields.limit) &&
  int(idx.settings.index.mapping.total_fields.limit) > 5000
))
```

**Message template:** {{count}} index/indices set index.mapping.total_fields.limit above 5000.

**Remediation:**

- Command: Investigate the producer creating fields; consider a fixed mapping or runtime fields rather than expanding the limit
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-settings-limit.html>
- `esops index settings`
- `esops index template`

---

## hygiene

### `cluster_health_status`

**Cluster health is not green**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | medium | hygiene, availability |

A non-green cluster has at least one shard the cluster considers unhealthy. Yellow is "primaries assigned, some replicas missing" — operationally tolerable but worth investigating before the next node failure makes it red. Red means at least one primary is unassigned and queries against the affected indices will fail.

- **Probe:** `cluster_health`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
has(self.status) && self.status == 'green'
```

**Count expression (CEL):**

```cel
(has(self.status) && self.status == 'green') ? 0 : 1
```

**Message template:** Cluster health is not green.

**Remediation:**

- Command: Check /_cluster/health and /_cluster/allocation/explain to identify which indices are non-green and why
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-health.html>
- `esops ops health`
- `esops ops shards`
- `esops ops allocation-explain`

---

### `default_cluster_name`

**Cluster is running with the distribution's default cluster name**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | low | hygiene, anti-pattern, prod |

Elasticsearch defaults cluster.name to "elasticsearch" and OpenSearch defaults to "opensearch". Leaving the default in place is the classic anti-pattern that lets two unrelated clusters discover each other when their nodes share an L2 segment, and it strips the operator-facing log/metric stream of the one identifier that distinguishes one cluster from another. Set cluster.name to a deliberate, environment-scoped value (prod-eu-1, staging-search, …) before the cluster grows past a single node.

- **Probe:** `cluster_health`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
has(self.cluster_name) &&
self.cluster_name != 'elasticsearch' &&
self.cluster_name != 'opensearch' &&
self.cluster_name != 'docker-cluster'
```

**Count expression (CEL):**

```cel
(has(self.cluster_name) &&
 self.cluster_name != 'elasticsearch' &&
 self.cluster_name != 'opensearch' &&
 self.cluster_name != 'docker-cluster') ? 0 : 1
```

**Message template:** cluster.name is set to the distribution default; pick a deliberate value.

**Remediation:**

- Command: Set cluster.name in elasticsearch.yml / opensearch.yml on every node and restart the cluster
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/important-settings.html#cluster-name>
- `esops ops health`

---

### `deprecation_log_critical`

**Critical deprecations reported by the cluster**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch | medium | hygiene, upgrade |

Issues at level critical from /_migration/deprecations block the next major-version upgrade. Every entry must be addressed before the cluster will accept the new binary; surface them now so the upgrade window doesn't surprise the operator.

- **Probe:** `deprecation_log`
- **Affected versions:** 7.x, 8.x, 9.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(d, !has(d.level) || d.level != 'critical')
```

**Count expression (CEL):**

```cel
size(self.filter(d, has(d.level) && d.level == 'critical'))
```

**Message template:** {{count}} critical deprecation(s) reported by /_migration/deprecations.

**Remediation:**

- Command: Run `esops-doctor scan --rule-id deprecation_log_critical --output json` to see each issue, then follow the per-issue url field to resolve
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/migration-api-deprecation.html>
- `esops ops deprecations`

---

### `deprecation_log_warning`

**Warning-level deprecations reported by the cluster**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch | medium | hygiene, upgrade |

Issues at level "warning" from /_migration/deprecations describe configuration the cluster will accept on the next major-version upgrade but will remove in a future release. Companion to deprecation_log_critical: critical entries block the next upgrade outright, warning entries give the operator a runway to fix things before they become critical. Surfacing the count here lets the operator schedule the work — typically as part of the same maintenance window as the upgrade itself.

- **Probe:** `deprecation_log`
- **Affected versions:** 7.x, 8.x, 9.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(d, !has(d.level) || d.level != 'warning')
```

**Count expression (CEL):**

```cel
size(self.filter(d, has(d.level) && d.level == 'warning'))
```

**Message template:** {{count}} warning-level deprecation(s) reported by /_migration/deprecations.

**Remediation:**

- Command: Run `esops-doctor scan --rule-id deprecation_log_warning --output json` to see each issue, then follow the per-issue url field to resolve
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/migration-api-deprecation.html>
- `esops ops deprecations`

---

### `network_host_wildcard`

**network.host bound to a wildcard address**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | medium | hygiene, anti-pattern, prod |

A node configured with network.host=0.0.0.0 (or the IPv6 equivalent ::, or the special _site_:_local_ chain that collapses to "every interface") publishes the cluster on every interface the host owns. That's the right answer in a single-tenant container with one network attached; in a prod deployment with a management interface and a data-plane interface it ships the cluster's HTTP and transport ports out to anything that can route to the host. Pin network.host to a specific address (or the well-known _site_ / _local_ aliases with no fallback) so the cluster only listens where the operator intended.

- **Probe:** `node_settings`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(n,
  !has(n.settings) ||
  !('network.host' in n.settings) ||
  (
    string(n.settings['network.host']) != '0.0.0.0' &&
    string(n.settings['network.host']) != '::' &&
    string(n.settings['network.host']) != '0:0:0:0:0:0:0:0'
  )
)
```

**Count expression (CEL):**

```cel
size(self.filter(n,
  has(n.settings) &&
  ('network.host' in n.settings) &&
  (
    string(n.settings['network.host']) == '0.0.0.0' ||
    string(n.settings['network.host']) == '::' ||
    string(n.settings['network.host']) == '0:0:0:0:0:0:0:0'
  )
))
```

**Message template:** {{count}} node(s) bind network.host to a wildcard address.

**Remediation:**

- Command: Pin network.host in elasticsearch.yml / opensearch.yml to a specific address (or _site_ / _local_) and restart the affected nodes
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-network.html>
- `esops ops nodes`

---

### `pending_task_accumulation`

**Cluster pending tasks have accumulated**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | medium | hygiene, performance |

A pending cluster-state update sitting in the queue for more than 30 seconds means the master node is bottlenecked — typical causes are a master under-resourced for the cluster size, a paused master election, or a flood of mapping updates from a misconfigured client. The threshold is intentionally loose; transient queue depth is normal during shard relocations.

- **Probe:** `pending_tasks`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(t,
  !has(t.time_in_queue_millis) ||
  int(t.time_in_queue_millis) < 30000
)
```

**Count expression (CEL):**

```cel
size(self.filter(t,
  has(t.time_in_queue_millis) &&
  int(t.time_in_queue_millis) >= 30000
))
```

**Message template:** {{count}} pending task(s) sitting in queue for ≥30 s.

**Remediation:**

- Command: Check the master node's load, GC pauses, and the source field of each pending task to identify the bottleneck
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-pending.html>
- `esops ops pending-tasks`
- `esops ops tasks list`
- `esops ops nodes`

---

### `remote_cluster_unreachable`

**Configured remote cluster is not currently reachable**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch, opensearch | medium | prod, availability |

A remote cluster registered for cross-cluster search or cross-cluster replication that the local cluster cannot reach means every CCS-targeted query and every CCR follower silently falls back to "no data" until the remote comes back. The cluster's own `connected: false` flag is the canonical signal — it survives transient network blips and only reports false when the remote has been unreachable long enough to matter. Operators with `skip_unavailable=true` set deliberately accept that some remotes drop in and out; rules that flag both connected=false AND skip_unavailable=false catch the riskier "search will hard- fail when the remote is gone" case.

- **Probe:** `remote_clusters`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(r, has(r.connected) && r.connected)
```

**Count expression (CEL):**

```cel
size(self.filter(r,
  has(r.connected) && !r.connected
))
```

**Message template:** {{count}} remote cluster(s) configured but not currently reachable.

**Remediation:**

- Command: Check the remote cluster's seed hosts (sniff mode) or proxy address (proxy mode) for reachability; either restore the link or de-register the remote via PUT /_cluster/settings if it is no longer needed
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/remote-clusters.html>
- `esops ops settings get`

---

### `suspect_discovery_settings`

**Discovery settings look like a single-node misconfiguration**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch, opensearch | high | hygiene, anti-pattern, prod |

Two anti-patterns this rule flags. (1) discovery.type=single-node on a node that is part of a multi-node cluster: the value disables the cluster-formation handshake entirely and is meant for laptops and CI containers; running it in prod produces a cluster that will never re-form a master after a restart. (2) An empty discovery.seed_hosts on a master-eligible node: with no seed list the node falls back to localhost-only discovery, which works on a single-node Docker image and silently breaks the moment a second node is added. Either signal points at config that worked on a developer's machine and got copied into prod unchanged.

- **Probe:** `node_settings`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) <= 1 ||
self.all(n,
  !has(n.settings) ||
  (
    (
      !('discovery.type' in n.settings) ||
      string(n.settings['discovery.type']) != 'single-node'
    ) &&
    (
      !('discovery.seed_hosts' in n.settings) ||
      (
        string(n.settings['discovery.seed_hosts']) != '' &&
        string(n.settings['discovery.seed_hosts']) != '[]'
      )
    )
  )
)
```

**Count expression (CEL):**

```cel
size(self) <= 1 ? 0 :
size(self.filter(n,
  has(n.settings) &&
  (
    (
      ('discovery.type' in n.settings) &&
      string(n.settings['discovery.type']) == 'single-node'
    ) ||
    (
      ('discovery.seed_hosts' in n.settings) &&
      (
        string(n.settings['discovery.seed_hosts']) == '' ||
        string(n.settings['discovery.seed_hosts']) == '[]'
      )
    )
  )
))
```

**Message template:** {{count}} node(s) carry single-node-mode or empty-seed-list discovery settings on a multi-node cluster.

**Remediation:**

- Command: Remove discovery.type=single-node and populate discovery.seed_hosts with the master-eligible nodes' transport addresses, then restart the affected nodes
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-discovery-settings.html>
- `esops ops nodes`

---

### `transient_settings_drift`

**Cluster has transient settings that will vanish on a full restart**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | low | hygiene, anti-pattern, prod |

Transient cluster settings live only in the in-memory cluster state and are wiped on a full cluster restart, leaving the cluster running with whatever the persistent scope (or the built-in default) reports. That makes them a classic source of silent regressions: an operator pushes a fix into the transient scope during an incident, the cluster recovers, and three months later a routine restart reverts the change with no audit trail. Promote anything important into the persistent scope — the only place a setting survives a restart. Newer Elasticsearch releases reject writes to the transient scope outright; this rule helps an operator clear the legacy state before that happens.

- **Probe:** `cluster_settings_full`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
!has(self.transient) ||
size(self.transient) == 0
```

**Count expression (CEL):**

```cel
has(self.transient) ? size(self.transient) : 0
```

**Message template:** {{count}} transient cluster setting(s) will vanish on a full restart.

**Remediation:**

- Command: Promote each transient setting into the persistent scope (or remove it) — `esops ops settings set --scope persistent KEY VALUE`, then PUT null to the transient scope
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-update-settings.html>
- `esops ops settings get`
- `esops ops settings set`

---

### `version_skew`

**Cluster nodes are not running the same version**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch, opensearch | medium | hygiene, upgrade |

A multi-node cluster that has more than one distinct version string across its /_cat/nodes view is in the middle of a rolling upgrade — or stuck in one. Running mixed versions for longer than a deliberate rolling-restart window is unsupported by both Elasticsearch and OpenSearch: the master refuses certain operations, allocation decisions get conservative, and deprecation handling diverges per-node. Surface the skew so the operator either finishes the upgrade or rolls back. Single-node clusters and nodes that do not report a version are skipped.

- **Probe:** `nodes`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) <= 1 ||
size(self.filter(n, has(n.version) && n.version != '')) <= 1 ||
self.filter(n, has(n.version) && n.version != '').all(n,
  n.version == self.filter(m, has(m.version) && m.version != '')[0].version
)
```

**Count expression (CEL):**

```cel
size(self.filter(n, has(n.version) && n.version != '')) <= 1 ? 0 :
size(self.filter(n,
  has(n.version) && n.version != '' &&
  n.version != self.filter(m, has(m.version) && m.version != '')[0].version
))
```

**Message template:** {{count}} node(s) running a version that does not match the rest of the cluster.

**Remediation:**

- Command: Complete the in-progress rolling upgrade, or roll back the divergent nodes — see /_cat/nodes for the per-node version
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/rolling-upgrades.html>
- `esops ops nodes`

---

## lifecycle

### `ccr_auto_follow_paused`

**Cross-cluster auto-follow pattern is paused**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch | low | prod, recoverability |

A paused auto-follow pattern (`active: false` in `/_ccr/auto_follow`) means new leader-side indices matching the pattern will not get a follower index created on the local cluster — replication for the existing followers continues, but the namespace stops widening. Maintenance windows commonly pause a pattern deliberately and the rule's job is to make sure that pause is intentional rather than a leftover from a paged-out operator. CCR auto-follow is Elasticsearch-only; the rule auto-skips on OpenSearch and on basic-licence Elasticsearch clusters where `/_ccr/auto_follow` is unregistered.

- **Probe:** `auto_follow_patterns`
- **Affected versions:** 7.x, 8.x, 9.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(p, !has(p.active) || p.active)
```

**Count expression (CEL):**

```cel
size(self.filter(p, has(p.active) && !p.active))
```

**Message template:** {{count}} CCR auto-follow pattern(s) are paused.

**Remediation:**

- Command: Resume the pattern via POST /_ccr/auto_follow/{name}/resume once the maintenance is done; if the pattern is no longer needed, delete it instead so it stops appearing in scans
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/ccr-getting-started.html>

---

### `ccr_follower_unhealthy`

**Cross-cluster replication follower is paused or has read failures**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch | medium | prod, recoverability, availability |

An Elasticsearch CCR follower index that is paused, or whose most recent read attempt failed, has stopped catching up to its leader — every minute it stays in that state is a minute the local copy drifts further behind. Both signals come from `/_ccr/stats`: `paused: true` is the operator-visible knob (typically engaged during a maintenance window) and `last_read_failure` carries the cluster's own description of the last failure, populated only while the follower is unhealthy. CCR is Elasticsearch-only; the rule auto-skips on OpenSearch clusters and on basic-licence Elasticsearch clusters where `/_ccr/stats` is not registered.

- **Probe:** `follower_stats`
- **Affected versions:** 7.x, 8.x, 9.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(f,
  (!has(f.paused) || !f.paused) &&
  (!has(f.last_read_failure) || f.last_read_failure == '')
)
```

**Count expression (CEL):**

```cel
size(self.filter(f,
  (has(f.paused) && f.paused) ||
  (has(f.last_read_failure) && f.last_read_failure != '')
))
```

**Message template:** {{count}} CCR follower index/indices are paused or surfacing read failures.

**Remediation:**

- Command: Inspect /_ccr/stats for the affected followers; resume paused follows once the maintenance is done, and follow up the last_read_failure with the leader-side cause (auth, network, mapping incompatibility)
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/ccr-getting-started.html>

---

### `ccr_lease_expiring`

**Cross-cluster replication retention lease is approaching expiry**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch | medium | prod, recoverability, availability |

A CCR follower index keeps a retention lease on every leader-side shard so the leader cluster preserves the operations the follower still needs to consume. The default lease retention period is 12 hours (`index.soft_deletes.retention_lease.period`); once a lease expires the leader is free to discard the operations the follower hasn't read yet, and the follower falls irrecoverably behind — re-bootstrap is the only fix. The probe surfaces the cluster's reported max retention-lease age across all of a follower index's shards (`retention_lease_age_in_millis` from `/_ccr/stats`), and the rule flags any follower whose lease has been alive longer than 6 hours, the half-default-period threshold an SRE wants to know about before the cluster goes irrecoverable. CCR is Elasticsearch-only; the rule auto-skips on OpenSearch and on basic-licence Elasticsearch clusters where `/_ccr/stats` is not registered. Older clusters that do not surface the lease-age field at all are treated as a vacuous pass (the field reads as absent and the condition short-circuits).

- **Probe:** `follower_stats`
- **Affected versions:** 7.x, 8.x, 9.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(f,
  !has(f.retention_lease_age_millis) ||
  int(f.retention_lease_age_millis) <= 21600000
)
```

**Count expression (CEL):**

```cel
size(self.filter(f,
  has(f.retention_lease_age_millis) &&
  int(f.retention_lease_age_millis) > 21600000
))
```

**Message template:** {{count}} CCR follower index/indices have a retention lease older than 6 hours.

**Remediation:**

- Command: Inspect /_ccr/stats for the affected followers; restore the leader-side connection (network, auth, licence) before the lease expires, otherwise re-bootstrap the follower from a recent snapshot
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/ccr-getting-started.html>

---

### `ilm_policy_present`

**At least one ILM policy is defined**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch | medium | prod, retention |

Time-series workloads on Elasticsearch belong on an Index Lifecycle Management policy so hot/warm/cold/delete transitions are automated rather than relying on manual rollover. A cluster with zero ILM policies is either pre-prod or has retention gaps; surface the absence so the operator can decide.

- **Probe:** `ilm_state`
- **Affected versions:** 7.x, 8.x, 9.x

**Condition (CEL):**

```cel
size(self) > 0
```

**Count expression (CEL):**

```cel
size(self)
```

**Message template:** No ILM policies are defined; time-series indices have no automated retention.

**Remediation:**

- Command: Define a policy with `esops index ilm apply --policy <name>`
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/index-lifecycle-management.html>
- `esops index ilm`

---

### `ism_policy_present`

**At least one ISM policy is defined**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | opensearch | medium | prod, retention |

Time-series workloads on OpenSearch belong on an Index State Management policy so retention transitions are automated rather than driven by ad-hoc index deletion. A cluster with zero ISM policies is either pre-prod or has retention gaps; surface the absence so the operator can decide.

- **Probe:** `ism_state`
- **Affected versions:** 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) > 0
```

**Count expression (CEL):**

```cel
size(self)
```

**Message template:** No ISM policies are defined; time-series indices have no automated retention.

**Remediation:**

- Command: Define an ISM policy that rolls over and deletes time-series indices on a schedule
- Doc: <https://opensearch.org/docs/latest/im-plugin/ism/index/>
- `esops index ism`

---

### `retention_gap`

**Snapshot schedule has a multi-day gap**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | medium | prod, recoverability |

The largest gap between consecutive SUCCESS snapshots in a repository — including the gap between the most recent SUCCESS and "now" — exceeds 7 days (168 hours). Catches the silent "snapshots have been failing for a week even though older successes exist" failure mode that snapshot_failed_state can miss when the operator has already pruned the FAILED entries. Repositories with fewer than two SUCCESS snapshots are skipped; the untested_restore rule covers the zero-success case.

- **Probe:** `snapshot_recency`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(r,
  !has(r.max_success_gap_hours) ||
  r.max_success_gap_hours <= 168.0
)
```

**Count expression (CEL):**

```cel
size(self.filter(r,
  has(r.max_success_gap_hours) &&
  r.max_success_gap_hours > 168.0
))
```

**Message template:** {{count}} repository/repositories have a SUCCESS-snapshot gap longer than 7 days.

**Remediation:**

- Command: Investigate the schedule for the affected repository — failed runs that were pruned still leave the gap; fix the underlying cause and re-run
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/snapshots-take-snapshot.html>
- `esops snapshot list`
- `esops snapshot verify`

---

### `snapshot_failed_state`

**Snapshots in FAILED state**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch, opensearch | medium | prod, recoverability |

A snapshot whose state is FAILED finished with at least one shard that did not write — the resulting snapshot cannot be relied on for restore. Surface every failure so the operator can prune the stale entry and re-run the SLM/SLS schedule.

- **Probe:** `snapshots`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(s, !has(s.state) || s.state != 'FAILED')
```

**Count expression (CEL):**

```cel
size(self.filter(s, has(s.state) && s.state == 'FAILED'))
```

**Message template:** {{count}} snapshot(s) finished with state FAILED.

**Remediation:**

- Command: Investigate the failure (ShardsFailed and Failures), prune the snapshot, and re-run the schedule
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/snapshots-take-snapshot.html>
- `esops snapshot list`
- `esops snapshot verify`
- `esops snapshot prune`

---

### `snapshot_partial_state`

**Snapshots in PARTIAL or INCOMPATIBLE state**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | low | prod, recoverability |

A snapshot in PARTIAL state captured some shards but not all; an INCOMPATIBLE snapshot was taken on a cluster version the current version cannot restore. Either way the entry is surprise-shaped for a future operator running `snapshot restore`. Flag both so the schedule can be cleaned up.

- **Probe:** `snapshots`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(s,
  !has(s.state) ||
  (s.state != 'PARTIAL' && s.state != 'INCOMPATIBLE')
)
```

**Count expression (CEL):**

```cel
size(self.filter(s,
  has(s.state) &&
  (s.state == 'PARTIAL' || s.state == 'INCOMPATIBLE')
))
```

**Message template:** {{count}} snapshot(s) in PARTIAL or INCOMPATIBLE state.

**Remediation:**

- Command: Prune the affected snapshots and re-run a clean schedule once the underlying cause (failed shards, version skew) is fixed
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/delete-snapshot-api.html>
- `esops snapshot list`
- `esops snapshot prune`

---

### `snapshot_repository_configured`

**At least one snapshot repository is registered**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| critical | elasticsearch, opensearch | medium | prod, recoverability |

A cluster with no registered snapshot repository has no path to recovery short of restoring source-of-truth elsewhere. Surface the absence loudly — this is a critical-severity finding because a single hardware failure becomes data loss without it.

- **Probe:** `snapshot_repositories`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) > 0
```

**Count expression (CEL):**

```cel
size(self)
```

**Message template:** No snapshot repository is registered; the cluster has no backup path.

**Remediation:**

- Command: Register a repository with `esops snapshot repo register --name <repo> --type <fs|s3|gcs|azure>` and schedule recurring snapshots
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/snapshots-register-repository.html>
- `esops snapshot list`

---

### `snapshot_slo_age`

**Most recent successful snapshot is stale**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch, opensearch | medium | prod, recoverability |

The most recent SUCCESS snapshot in a repository is older than 48 hours — past the point where "snapshots run nightly" can still be true. snapshot_repository_configured tells you the repo exists; snapshot_failed_state tells you the most recent attempt didn't crash; this rule tells you the schedule is actually producing fresh, restorable snapshots. Repositories with zero SUCCESS snapshots are skipped — that's the untested_restore rule's job.

- **Probe:** `snapshot_recency`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(r,
  !has(r.latest_success_age_hours) ||
  r.latest_success_age_hours <= 48.0
)
```

**Count expression (CEL):**

```cel
size(self.filter(r,
  has(r.latest_success_age_hours) &&
  r.latest_success_age_hours > 48.0
))
```

**Message template:** {{count}} repository/repositories have no SUCCESS snapshot in the last 48 hours.

**Remediation:**

- Command: Check the schedule (SLM on Elasticsearch, SM on OpenSearch) for the affected repository, fix the cause of the failures, and re-run
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/snapshot-lifecycle-management.html>
- `esops snapshot list`
- `esops snapshot verify`

---

### `untested_restore`

**Snapshot repository has never produced a successful snapshot**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch, opensearch | medium | prod, recoverability |

A snapshot repository that contains snapshots but has zero SUCCESS-state entries is a repository nobody has confirmed end-to-end restore-readiness against. Either every attempt failed (in which case the schedule is dressed-up no-op) or the operator never came back to verify the SUCCESS path. The repository is dressed-up data loss waiting to happen — flag it so the operator can run a targeted restore-into-staging test and either fix the schedule or remove the dead repo.

- **Probe:** `snapshot_recency`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(r,
  r.snapshot_count == 0 ||
  r.success_count > 0
)
```

**Count expression (CEL):**

```cel
size(self.filter(r,
  r.snapshot_count > 0 &&
  r.success_count == 0
))
```

**Message template:** {{count}} snapshot repository/repositories have snapshots but no SUCCESS entry.

**Remediation:**

- Command: Run a restore-into-staging test against the repository, then fix whatever caused every attempt to fail (permissions, disk, plugin) and re-run the schedule
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/snapshots-restore-snapshot.html>
- `esops snapshot list`
- `esops snapshot verify`

---

## mappings

### `catchall_index_template`

**Composable template with a catch-all index pattern**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | low | hygiene, mappings |

A template whose index_patterns contains a bare "*" matches every future index — including ones a more specific template was meant to govern. Catch-all templates make mapping behaviour depend on template-priority race conditions and silently catch operator- created scratch indices.

- **Probe:** `index_templates`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(t,
  !has(t.index_patterns) ||
  !t.index_patterns.exists(p, p == '*')
)
```

**Count expression (CEL):**

```cel
size(self.filter(t,
  has(t.index_patterns) &&
  t.index_patterns.exists(p, p == '*')
))
```

**Message template:** {{count}} composable template(s) with a bare "*" index pattern.

**Remediation:**

- Command: Replace the catch-all "*" pattern with a specific prefix (e.g. "logs-*", "metrics-*") so the template only matches its intended indices
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/index-templates.html>
- `esops index template`

---

### `composable_template_priority`

**Composable index template missing priority**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | low | hygiene, mappings |

Composable (v2) index templates without an explicit priority default to zero. When two templates' index_patterns overlap the cluster picks the higher-priority template — falling back on ordering implicit at zero is fragile, and silent surprises here land as broken mappings on freshly-created indices.

- **Probe:** `index_templates`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(t,
  has(t.priority) && int(t.priority) > 0
)
```

**Count expression (CEL):**

```cel
size(self.filter(t,
  !has(t.priority) || int(t.priority) == 0
))
```

**Message template:** {{count}} composable template(s) without an explicit priority.

**Remediation:**

- Command: Set a non-zero priority on the affected templates so overlapping patterns resolve deterministically
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/index-templates.html>
- `esops index template`

---

### `deeply_nested_objects`

**Mapping nests objects more than 4 levels deep**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | high | prod, mappings |

Deeply-nested object mappings make every field-resolution walk slower and push the per-document field count up sharply (each sub-object at depth N multiplies the leaf count). The reference guidance is ≤3–4 levels of nested objects; doctor flags any index whose mapping carries a path through five `properties` chains (i.e. four nested objects beneath the root). System indices are excluded — their schema is the cluster's call.

- **Probe:** `mappings`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(idx,
  !has(idx.name) ||
  idx.name.startsWith('.') ||
  !has(idx.properties) ||
  !idx.properties.exists(a,
    has(idx.properties[a].properties) &&
    idx.properties[a].properties.exists(b,
      has(idx.properties[a].properties[b].properties) &&
      idx.properties[a].properties[b].properties.exists(c,
        has(idx.properties[a].properties[b].properties[c].properties) &&
        idx.properties[a].properties[b].properties[c].properties.exists(d,
          has(idx.properties[a].properties[b].properties[c].properties[d].properties) &&
          size(idx.properties[a].properties[b].properties[c].properties[d].properties) > 0
        )
      )
    )
  )
)
```

**Count expression (CEL):**

```cel
size(self.filter(idx,
  has(idx.name) && !idx.name.startsWith('.') &&
  has(idx.properties) &&
  idx.properties.exists(a,
    has(idx.properties[a].properties) &&
    idx.properties[a].properties.exists(b,
      has(idx.properties[a].properties[b].properties) &&
      idx.properties[a].properties[b].properties.exists(c,
        has(idx.properties[a].properties[b].properties[c].properties) &&
        idx.properties[a].properties[b].properties[c].properties.exists(d,
          has(idx.properties[a].properties[b].properties[c].properties[d].properties) &&
          size(idx.properties[a].properties[b].properties[c].properties[d].properties) > 0
        )
      )
    )
  )
))
```

**Message template:** {{count}} index/indices have mapping nested deeper than 4 levels.

**Remediation:**

- Command: Flatten the deeply-nested objects into named scalar fields, or move the structure into a child index referenced by id
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-settings-limit.html>
- `esops index template`
- `esops migrate reindex`

---

### `deprecated_field_types`

**Mapping uses deprecated field types**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | high | prod, mappings |

Surfaces fields whose `type` is one the cluster has marked deprecated or removed in a current major version. The classic offender is `string` (split into `text` + `keyword` in 5.0); a few more recent additions — `_all`, the legacy `geo_point` string format, and the deprecated `flattened` shape — round out the set. A reindex is the only path to a clean mapping; flagging these early gives the operator time to plan it. System indices (dot-prefixed) are excluded — their schema is the cluster's call.

- **Probe:** `mapping_fields`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(f,
  f.is_system ||
  !(f.type in ['string', '_all', 'token_count_legacy'])
)
```

**Count expression (CEL):**

```cel
size(self.filter(f,
  !f.is_system &&
  f.type in ['string', '_all', 'token_count_legacy']
))
```

**Message template:** {{count}} field(s) in non-system indices use a deprecated field type.

**Remediation:**

- Command: Update the index template to use the modern field type and reindex affected indices so the live mapping matches
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/removal-of-types.html>
- `esops index template`
- `esops migrate reindex`

---

### `dynamic_mapping_strict`

**Index allows dynamic mapping**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | medium | prod, mappings |

With dynamic mapping enabled (the cluster default), unknown fields in incoming documents silently become new mapping entries — a single misconfigured client can push the index past its total_fields.limit, blowing up indexing for every other writer. Recommended posture for production indices is `dynamic: strict` (rejects unknown fields) or `dynamic: false` (ignores them). System indices (dot-prefixed) and data-stream backing indices are excluded — their mapping is the cluster's call.

- **Probe:** `mappings`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(idx,
  !has(idx.name) ||
  idx.name.startsWith('.') ||
  (has(idx.dynamic) && (idx.dynamic == 'strict' || idx.dynamic == 'false'))
)
```

**Count expression (CEL):**

```cel
size(self.filter(idx,
  has(idx.name) && !idx.name.startsWith('.') &&
  (!has(idx.dynamic) || (idx.dynamic != 'strict' && idx.dynamic != 'false'))
))
```

**Message template:** {{count}} non-system index/indices accept dynamic mapping.

**Remediation:**

- Command: Set `dynamic: strict` (or `false`) on the index template so future indices reject (or ignore) unknown fields, and run a reindex if the existing mapping needs the same posture
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/dynamic.html>
- `esops index template`
- `esops migrate reindex`

---

### `mapping_template_drift`

**Live index drifted from its composable template**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | medium | prod, mappings |

A live index whose top-level `dynamic` setting does not match the v2 composable template that claims its name. Drift like this is usually the trail of a hand-edited mapping that the next rollover will silently undo, or — worse — a template whose promise of `strict` ingest never made it past the first index rollover. Surface the gap so the operator can either re-apply the template (and reindex, if the live shape needs the same stance) or update the template to reflect the live behaviour they actually want.

- **Probe:** `mapping_drift`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0
```

**Count expression (CEL):**

```cel
size(self)
```

**Message template:** {{count}} live index/indices drifted from their composable template's dynamic setting.

**Remediation:**

- Command: Re-apply the composable template (`esops index template`) and reindex so the live mapping matches, or update the template to match the live behaviour you want
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/index-templates.html>
- `esops index template`
- `esops migrate reindex`

---

### `template_no_index_patterns`

**Composable template with empty index_patterns**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch, opensearch | low | hygiene, mappings |

A composable template with no index_patterns matches nothing — the cluster accepted it but no future index will pick up its settings, mappings, or aliases. Almost always a copy-paste mistake; surface it so the operator can either fix the patterns or remove the dead template.

- **Probe:** `index_templates`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(t,
  has(t.index_patterns) && size(t.index_patterns) > 0
)
```

**Count expression (CEL):**

```cel
size(self.filter(t,
  !has(t.index_patterns) || size(t.index_patterns) == 0
))
```

**Message template:** {{count}} composable template(s) with no index_patterns set.

**Remediation:**

- Command: Add at least one index pattern to the template (or delete the template if it is unused)
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/index-templates.html>
- `esops index template`

---

### `unbounded_keyword_cardinality`

**Keyword field without ignore_above**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | medium | prod, mappings |

A `keyword` field with no `ignore_above` set will index any string the cluster receives, no matter how long. A single runaway document (a 10KB stack-trace shoved into a keyword-typed log field) can blow past Lucene's per-document term-byte limit and reject the whole document, or silently push the field's cardinality high enough to wreck aggregation performance. The Elastic Common Schema default of 1024 is a reasonable cap; this rule flags only fields that set no cap at all. System indices (dot-prefixed) are excluded.

- **Probe:** `mapping_fields`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(f,
  f.is_system ||
  f.type != 'keyword' ||
  f.has_ignore_above
)
```

**Count expression (CEL):**

```cel
size(self.filter(f,
  !f.is_system &&
  f.type == 'keyword' &&
  !f.has_ignore_above
))
```

**Message template:** {{count}} keyword field(s) in non-system indices have no ignore_above cap.

**Remediation:**

- Command: Set `ignore_above` (1024 is the ECS default) on the keyword field in the index template, then reindex to apply the cap to the live data
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/ignore-above.html>
- `esops index template`
- `esops migrate reindex`

---

## resource_sanity

### `circuit_breaker_limits`

**Circuit-breaker limits overridden by the operator**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch, opensearch | low | prod, resource, performance |

The cluster's circuit breakers are the last line of defence against OOM-killing the JVM: the parent breaker (`indices.breaker.total.limit`, default 95% of heap), the field-data breaker (`indices.breaker.fielddata.limit`, default 40%), and the in-flight-request breaker (`indices.breaker.request.limit`, default 60%) cooperatively reject queries that would tip a node over before the JVM exits with no record of who fired the gun. An operator narrowing any of these is almost always silencing a noisy breaker rather than fixing the workload that tripped it — which removes the protection without removing the cause. Flag every cluster that has one of these breaker keys set in the persistent or transient scope so a human can review the override against the defaults; the override may be intentional, but it should never be a surprise.

- **Probe:** `cluster_settings_full`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
(
  !has(self.persistent) ||
  (!('indices.breaker.total.limit' in self.persistent) &&
   !('indices.breaker.fielddata.limit' in self.persistent) &&
   !('indices.breaker.request.limit' in self.persistent))
) &&
(
  !has(self.transient) ||
  (!('indices.breaker.total.limit' in self.transient) &&
   !('indices.breaker.fielddata.limit' in self.transient) &&
   !('indices.breaker.request.limit' in self.transient))
)
```

**Count expression (CEL):**

```cel
(
  (has(self.persistent) && 'indices.breaker.total.limit' in self.persistent) ||
  (has(self.transient) && 'indices.breaker.total.limit' in self.transient)
  ? 1 : 0
) +
(
  (has(self.persistent) && 'indices.breaker.fielddata.limit' in self.persistent) ||
  (has(self.transient) && 'indices.breaker.fielddata.limit' in self.transient)
  ? 1 : 0
) +
(
  (has(self.persistent) && 'indices.breaker.request.limit' in self.persistent) ||
  (has(self.transient) && 'indices.breaker.request.limit' in self.transient)
  ? 1 : 0
)
```

**Message template:** {{count}} circuit-breaker limit(s) overridden away from the cluster default.

**Remediation:**

- Command: Restore the cluster-default breaker limits via PUT /_cluster/settings (parent 95%, fielddata 40%, request 60%) and triage whichever workload tripped the breaker rather than silencing it
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/circuit-breaker.html>
- `esops ops settings get`
- `esops ops settings set`

---

### `dedicated_master_nodes`

**Dedicated master-eligible nodes**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch, opensearch | medium | prod, availability |

Production clusters should run at least three dedicated master-eligible nodes (master role, no data role) so master elections survive a single-node failure without contention from data-path workload. Skipped on single-node and two-node clusters where the dedicated-master pattern doesn't apply.

- **Probe:** `nodes`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) < 3 ||
size(self.filter(n,
  has(n.roles) &&
  n.roles.exists(r, r == 'master') &&
  !n.roles.exists(r, r == 'data' || r.startsWith('data_'))
)) >= 3
```

**Count expression (CEL):**

```cel
size(self.filter(n,
  has(n.roles) &&
  n.roles.exists(r, r == 'master') &&
  !n.roles.exists(r, r == 'data' || r.startsWith('data_'))
))
```

**Message template:** Found {{count}} dedicated master-eligible nodes; want at least 3.

**Remediation:**

- Command: Add three master-only nodes (node.roles=[master]) and remove the data role from the existing master-eligible nodes
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-node.html>
- `esops ops nodes`

---

### `delayed_unassigned_shards`

**Cluster has delayed unassigned shards**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | low | prod, availability |

Delayed-unassigned shards are replicas the cluster is intentionally withholding from allocation while it waits for a node to come back (index.unassigned.node_left.delayed_timeout). A persistent count here means the timeout is overdue and a node has not returned — the cluster is one node failure away from data loss on those shards' indices.

- **Probe:** `cluster_health`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
!has(self.delayed_unassigned_shards) || int(self.delayed_unassigned_shards) == 0
```

**Count expression (CEL):**

```cel
has(self.delayed_unassigned_shards) ? int(self.delayed_unassigned_shards) : 0
```

**Message template:** {{count}} shard(s) flagged as delayed-unassigned by /_cluster/health.

**Remediation:**

- Command: Bring the missing node back online or rejoin replacement capacity to the cluster so the delayed allocation can resume
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/delayed-allocation.html>
- `esops ops nodes`
- `esops ops allocation-explain`
- `esops ops shards`

---

### `disk_watermarks`

**Disk usage approaching low watermark**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch, opensearch | medium | prod, capacity |

Once a node passes 85% disk usage the cluster's low watermark stops new shard allocations to it; at 90% the high watermark starts relocating shards off; at 95% indices flip to read-only. Flag any data node already at or above 85% so an operator can add capacity before allocation stalls.

- **Probe:** `nodes`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(n,
  !has(n.disk_used_percent) || int(n.disk_used_percent) < 85
)
```

**Count expression (CEL):**

```cel
size(self.filter(n,
  has(n.disk_used_percent) && int(n.disk_used_percent) >= 85
))
```

**Message template:** {{count}} node(s) at or above 85% disk usage (low watermark).

**Remediation:**

- Command: Free disk on the affected node, expand the underlying volume, or relocate shards via cluster.routing.allocation.exclude._name
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-cluster.html#disk-based-shard-allocation>
- `esops ops nodes`
- `esops ops drain`
- `esops ops unblock`

---

### `heap_size`

**JVM heap size configuration**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| critical | elasticsearch, opensearch | medium | prod, performance |

JVM heap should be ~50% of physical RAM and capped at 31 GiB so that compressed object pointers stay enabled. Nodes that do not report JVM info (coordinating-only or stripped builds) are skipped via the !has() guard.

- **Probe:** `node_stats`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) > 0 &&
self.all(node,
  !has(node.jvm) || !has(node.jvm.heap) || !has(node.jvm.heap.max_bytes) ||
  (
    int(node.jvm.heap.max_bytes) <= 31 * 1024 * 1024 * 1024 &&
    (
      !has(node.os) || !has(node.os.total_physical_memory_bytes) ||
      int(node.jvm.heap.init_bytes) * 2 <= int(node.os.total_physical_memory_bytes)
    )
  )
)
```

**Count expression (CEL):**

```cel
size(self.filter(node,
  has(node.jvm) && has(node.jvm.heap) && has(node.jvm.heap.max_bytes) &&
  (
    int(node.jvm.heap.max_bytes) > 31 * 1024 * 1024 * 1024 ||
    (
      has(node.os) && has(node.os.total_physical_memory_bytes) &&
      int(node.jvm.heap.init_bytes) * 2 > int(node.os.total_physical_memory_bytes)
    )
  )
))
```

**Message template:** Heap size misconfigured on {{count}} nodes.

**Remediation:**

- Command: Update JVM options and restart nodes
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/heap-size.html>
- `esops ops nodes`

---

### `index_legacy_box_routing`

**Index uses legacy box-style allocation attribute routing**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | medium | hygiene, capacity, upgrade |

Pre-data-tier deployments routed indices between hot / warm / cold groups by writing a node attribute (`node.attr.box_type`) and pointing the index at it via `index.routing.allocation.{include,require,exclude}.box_type`. Modern clusters use the typed `_tier_preference` setting and the `data_hot` / `data_warm` / `data_cold` / `data_frozen` / `data_content` node roles, which the cluster's allocator and ILM both understand natively. Legacy box routing still works for the moment, but it does not cooperate with ILM tier-based lifecycle actions and is the canonical "we forgot to migrate this index" finding during a rolling upgrade. System and data-stream backing indices are excluded — their allocation is the cluster's call.

- **Probe:** `index_settings`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(idx,
  !has(idx.index) || idx.index.startsWith('.') ||
  !has(idx.settings) ||
  !has(idx.settings.index) ||
  !has(idx.settings.index.routing) ||
  !has(idx.settings.index.routing.allocation) ||
  (
    (
      !has(idx.settings.index.routing.allocation.include) ||
      !has(idx.settings.index.routing.allocation.include.box_type)
    ) &&
    (
      !has(idx.settings.index.routing.allocation.require) ||
      !has(idx.settings.index.routing.allocation.require.box_type)
    ) &&
    (
      !has(idx.settings.index.routing.allocation.exclude) ||
      !has(idx.settings.index.routing.allocation.exclude.box_type)
    )
  )
)
```

**Count expression (CEL):**

```cel
size(self.filter(idx,
  has(idx.index) && !idx.index.startsWith('.') &&
  has(idx.settings) &&
  has(idx.settings.index) &&
  has(idx.settings.index.routing) &&
  has(idx.settings.index.routing.allocation) &&
  (
    (
      has(idx.settings.index.routing.allocation.include) &&
      has(idx.settings.index.routing.allocation.include.box_type)
    ) ||
    (
      has(idx.settings.index.routing.allocation.require) &&
      has(idx.settings.index.routing.allocation.require.box_type)
    ) ||
    (
      has(idx.settings.index.routing.allocation.exclude) &&
      has(idx.settings.index.routing.allocation.exclude.box_type)
    )
  )
))
```

**Message template:** {{count}} index/indices use legacy box_type allocation attributes instead of data tiers.

**Remediation:**

- Command: Migrate each affected index to `index.routing.allocation.include._tier_preference`; rewrite the source ILM policy or index template so the next rollover lands on the typed tier surface, then PUT null on the legacy box_type setting
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/migrate-to-data-tiers.html>
- `esops index settings`
- `esops index template`

---

### `index_max_result_window_high`

**Index raises max_result_window past the safe-default ceiling**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | medium | prod, performance |

The default `index.max_result_window` is 10 000 — the cluster's cap on `from + size` for a single search request. Raising it lets a paginated client request the 100 000th result through the coordinating node's heap; raising it further turns a single bad request into an OOM. Production indices that genuinely need "the deep history" use `search_after` or `point_in_time` and leave the window alone; the rule consumer flags any index that has pushed the window past 50 000 so that an SRE can confirm the trade-off was deliberate. System indices (dot-prefixed) and data-stream backing indices (`.ds-*`) are excluded — their windows are the cluster's call.

- **Probe:** `index_settings`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(idx,
  !has(idx.index) ||
  idx.index.startsWith('.') ||
  !has(idx.settings) ||
  !has(idx.settings.index) ||
  !has(idx.settings.index.max_result_window) ||
  int(idx.settings.index.max_result_window) <= 50000
)
```

**Count expression (CEL):**

```cel
size(self.filter(idx,
  has(idx.index) && !idx.index.startsWith('.') &&
  has(idx.settings) &&
  has(idx.settings.index) &&
  has(idx.settings.index.max_result_window) &&
  int(idx.settings.index.max_result_window) > 50000
))
```

**Message template:** {{count}} index/indices set index.max_result_window above 50000.

**Remediation:**

- Command: Restore index.max_result_window to the cluster default and migrate the offending consumer to search_after / point_in_time pagination
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/index-modules.html#dynamic-index-settings>
- `esops index settings`

---

### `index_tier_no_eligible_node`

**Index tier preference does not match any node in the cluster**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch, opensearch | medium | prod, capacity, availability |

An index whose `index.routing.allocation.include._tier_preference` lists tiers that no live node serves cannot be allocated by the cluster — its primaries either stay unassigned or fall back to whatever tier the cluster's resolver picks. The two failure modes look identical to an operator: shards in `unassigned`, or shards assigned to nodes the operator did not intend. This rule cross- references the per-index preference list with each node's data-tier roles (`data_hot`, `data_warm`, `data_cold`, `data_frozen`, `data_content`) and flags any index whose preference set has zero overlap with any node's tier set. System and data-stream backing indices (dot-prefixed) are excluded — their tier preferences are managed by the cluster, not the operator.

- **Probe:** `tier_layout`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
!has(self.indices) || size(self.indices) == 0 ||
self.indices.all(idx,
  !has(idx.name) || idx.name.startsWith('.') ||
  !has(idx.preferred_tiers) || size(idx.preferred_tiers) == 0 ||
  idx.preferred_tiers.exists(t,
    has(self.nodes) &&
    self.nodes.exists(n,
      has(n.tiers) && n.tiers.exists(nt, nt == t)
    )
  )
)
```

**Count expression (CEL):**

```cel
has(self.indices) ?
  size(self.indices.filter(idx,
    has(idx.name) && !idx.name.startsWith('.') &&
    has(idx.preferred_tiers) && size(idx.preferred_tiers) > 0 &&
    idx.preferred_tiers.all(t,
      !has(self.nodes) ||
      !self.nodes.exists(n,
        has(n.tiers) && n.tiers.exists(nt, nt == t)
      )
    )
  )) : 0
```

**Message template:** {{count}} index/indices request a data tier no node currently provides.

**Remediation:**

- Command: Add a node with the missing data-tier role (`data_hot`, `data_warm`, etc.) or rewrite the offending index's _tier_preference toward a tier the cluster actually has; check the source ILM policy or index template so the next rollover does not repeat the placement
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/data-tiers.html>
- `esops index settings`
- `esops ops nodes`

---

### `index_tier_preference_invalid`

**Index tier preference references an unknown data tier**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch, opensearch | low | prod, capacity |

The `index.routing.allocation.include._tier_preference` setting lets an index pin itself to one of the cluster's named data tiers — `data_hot`, `data_warm`, `data_cold`, `data_frozen`, or `data_content`. A typo (`data_warn` for `data_warm`) produces a preference the cluster cannot satisfy: the index's shards stay unassigned until an operator notices, or migrate to whatever tier the fallback resolves to. Flag any non-system index whose tier preference list contains an unrecognised tier so the typo is caught before the next ILM rollover replicates the mistake across every backing index. System and data-stream backing indices (dot-prefixed) are excluded — their tier preference is managed by the cluster, not the operator.

- **Probe:** `index_settings`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(idx,
  !has(idx.index) ||
  idx.index.startsWith('.') ||
  !has(idx.settings) ||
  !has(idx.settings.index) ||
  !has(idx.settings.index.routing) ||
  !has(idx.settings.index.routing.allocation) ||
  !has(idx.settings.index.routing.allocation.include) ||
  !has(idx.settings.index.routing.allocation.include._tier_preference) ||
  string(idx.settings.index.routing.allocation.include._tier_preference)
    .matches('^(data_hot|data_warm|data_cold|data_frozen|data_content)(,(data_hot|data_warm|data_cold|data_frozen|data_content))*$')
)
```

**Count expression (CEL):**

```cel
size(self.filter(idx,
  has(idx.index) && !idx.index.startsWith('.') &&
  has(idx.settings) &&
  has(idx.settings.index) &&
  has(idx.settings.index.routing) &&
  has(idx.settings.index.routing.allocation) &&
  has(idx.settings.index.routing.allocation.include) &&
  has(idx.settings.index.routing.allocation.include._tier_preference) &&
  !string(idx.settings.index.routing.allocation.include._tier_preference)
    .matches('^(data_hot|data_warm|data_cold|data_frozen|data_content)(,(data_hot|data_warm|data_cold|data_frozen|data_content))*$')
))
```

**Message template:** {{count}} index/indices have a tier preference referencing an unknown data tier.

**Remediation:**

- Command: Update the offending index's index.routing.allocation.include._tier_preference to a comma-separated list of {data_hot, data_warm, data_cold, data_frozen, data_content}; fix the source ILM policy or index template so the next rollover does not repeat the typo
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/data-tiers.html>
- `esops index settings`

---

### `jvm_gc_ergonomics`

**JVM GC algorithm or arguments fight the cluster's heuristics**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | medium | performance, resource |

Two patterns this rule flags. (1) A node still running the Concurrent Mark Sweep collector (gc_collectors contains "ConcurrentMarkSweep" or "ParNew"). CMS was deprecated in JDK 9, removed in JDK 14, and both Elasticsearch 8+ and OpenSearch 2+ default to G1GC out of the box — a node still on CMS is on a JDK old enough to be a security and a stability risk. (2) A node whose jvm_input_arguments override G1's pause-target heuristics (-XX:MaxGCPauseMillis, -XX:G1HeapRegionSize, -XX:InitiatingHeapOccupancyPercent) with manual values. The cluster's defaults are tuned against the actual heap and shard counts the operator has; an override that beat the defaults a release ago typically loses ground with each JVM update. Surface the overrides so the operator either documents the workload that demands them or removes them.

- **Probe:** `node_bootstrap`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(n,
  (
    !has(n.gc_collectors) ||
    !n.gc_collectors.exists(gc,
      gc.contains('ConcurrentMarkSweep') ||
      gc.contains('ParNew') ||
      gc == 'CMS'
    )
  ) &&
  (
    !has(n.jvm_input_arguments) ||
    !n.jvm_input_arguments.exists(arg,
      arg.startsWith('-XX:MaxGCPauseMillis') ||
      arg.startsWith('-XX:G1HeapRegionSize') ||
      arg.startsWith('-XX:InitiatingHeapOccupancyPercent') ||
      arg.startsWith('-XX:+UseConcMarkSweepGC') ||
      arg.startsWith('-XX:+UseParallelGC') ||
      arg.startsWith('-XX:+UseSerialGC')
    )
  )
)
```

**Count expression (CEL):**

```cel
size(self.filter(n,
  (
    has(n.gc_collectors) &&
    n.gc_collectors.exists(gc,
      gc.contains('ConcurrentMarkSweep') ||
      gc.contains('ParNew') ||
      gc == 'CMS'
    )
  ) ||
  (
    has(n.jvm_input_arguments) &&
    n.jvm_input_arguments.exists(arg,
      arg.startsWith('-XX:MaxGCPauseMillis') ||
      arg.startsWith('-XX:G1HeapRegionSize') ||
      arg.startsWith('-XX:InitiatingHeapOccupancyPercent') ||
      arg.startsWith('-XX:+UseConcMarkSweepGC') ||
      arg.startsWith('-XX:+UseParallelGC') ||
      arg.startsWith('-XX:+UseSerialGC')
    )
  )
))
```

**Message template:** {{count}} node(s) running CMS, an alternate collector, or manually-tuned G1 heuristics that fight the cluster default.

**Remediation:**

- Command: Remove CMS / Parallel / Serial collector flags and any G1 pause-target / region-size overrides from jvm.options.d, then restart the affected nodes — the cluster default is G1GC with pause targets the runtime tunes itself
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/advanced-configuration.html#set-jvm-options>
- `esops ops nodes`

---

### `node_store_allow_mmap`

**node.store.allow_mmap is disabled**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | medium | performance, resource |

Setting node.store.allow_mmap=false drops the cluster off the mmapfs / hybridfs store types and forces niofs for every shard on the affected node. That eliminates the page-cache-backed fast path Lucene was designed around: term dictionaries, doc values, and points trees that the kernel would have served from memory on a hot index now go through a userspace read syscall on every miss. The setting exists as an escape hatch for hosts where vm.max_map_count cannot be raised — fix the kernel limit and clear this flag rather than living with the degraded store. A bootstrap-check failure on max_map_count is the only legitimate reason to disable mmap; this rule fires on every other case.

- **Probe:** `node_settings`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(n,
  !has(n.settings) ||
  !('node.store.allow_mmap' in n.settings) ||
  string(n.settings['node.store.allow_mmap']) != 'false'
)
```

**Count expression (CEL):**

```cel
size(self.filter(n,
  has(n.settings) &&
  ('node.store.allow_mmap' in n.settings) &&
  string(n.settings['node.store.allow_mmap']) == 'false'
))
```

**Message template:** {{count}} node(s) have node.store.allow_mmap=false; the cluster is on niofs and slower for it.

**Remediation:**

- Command: Raise vm.max_map_count to at least 262144 on the affected hosts (sysctl -w vm.max_map_count=262144 plus a sysctl.d entry), then remove node.store.allow_mmap from the node config and restart
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/index-modules-store.html>
- `esops ops nodes`

---

### `search_default_limits`

**Search default limits raised to a high blast-radius value**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | medium | prod, resource, performance |

Cluster-level search defaults bound how much memory a single query (or scroll) can pull through the coordinating node before the search subsystem refuses. `search.max_buckets` (default 65 535) caps aggregation bucket counts; `search.max_open_scroll_context` (default 500) caps the number of scroll contexts a node will hold open for a slow consumer. Raising either of these to a value an order of magnitude past the default is the canonical "it worked on my laptop" anti- pattern that turns one expensive query into a cluster-wide incident. Flag persistent or transient overrides at or above the thresholds an SRE would raise an eyebrow at: 250 000 buckets, 5 000 scroll contexts.

- **Probe:** `cluster_settings_full`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
(
  !has(self.persistent) ||
  !('search.max_buckets' in self.persistent) ||
  int(string(self.persistent['search.max_buckets'])) < 250000
) &&
(
  !has(self.transient) ||
  !('search.max_buckets' in self.transient) ||
  int(string(self.transient['search.max_buckets'])) < 250000
) &&
(
  !has(self.persistent) ||
  !('search.max_open_scroll_context' in self.persistent) ||
  int(string(self.persistent['search.max_open_scroll_context'])) < 5000
) &&
(
  !has(self.transient) ||
  !('search.max_open_scroll_context' in self.transient) ||
  int(string(self.transient['search.max_open_scroll_context'])) < 5000
)
```

**Count expression (CEL):**

```cel
(
  (has(self.persistent) && 'search.max_buckets' in self.persistent &&
   int(string(self.persistent['search.max_buckets'])) >= 250000) ||
  (has(self.transient) && 'search.max_buckets' in self.transient &&
   int(string(self.transient['search.max_buckets'])) >= 250000)
  ? 1 : 0
) +
(
  (has(self.persistent) && 'search.max_open_scroll_context' in self.persistent &&
   int(string(self.persistent['search.max_open_scroll_context'])) >= 5000) ||
  (has(self.transient) && 'search.max_open_scroll_context' in self.transient &&
   int(string(self.transient['search.max_open_scroll_context'])) >= 5000)
  ? 1 : 0
)
```

**Message template:** {{count}} cluster-level search limit(s) raised past the safe-default threshold.

**Remediation:**

- Command: Lower search.max_buckets / search.max_open_scroll_context back toward defaults via PUT /_cluster/settings; investigate the workload that demanded the override and budget the right query, not the right ceiling
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/search-settings.html>
- `esops ops settings get`
- `esops ops settings set`

---

### `shard_count_per_node`

**Per-node shard count above recommendation**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | high | prod, performance |

Each shard carries fixed metadata, segment-cache, and FD overhead on its hosting node. Once a node passes ~600 shards the master's cluster-state messages, recovery times, and search-thread-pool pressure all degrade. Flag any node above the documented ~600 ceiling. The "UNASSIGNED" pseudo-row /_cat/allocation reports is excluded — it counts shards waiting for placement, not shards pinned to a real node.

- **Probe:** `allocation`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(n,
  !has(n.name) || n.name == 'UNASSIGNED' ||
  !has(n.shards) || int(n.shards) <= 600
)
```

**Count expression (CEL):**

```cel
size(self.filter(n,
  has(n.name) && n.name != 'UNASSIGNED' &&
  has(n.shards) && int(n.shards) > 600
))
```

**Message template:** {{count}} node(s) hosting more than 600 shards.

**Remediation:**

- Command: Reduce shard count via rollover/shrink, increase node count, or raise cluster.max_shards_per_node only after addressing the underlying sharding strategy
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/size-your-shards.html>
- `esops ops shards`
- `esops ops nodes`
- `esops index rollover`
- `esops index shrink`

---

### `shard_size_distribution`

**Average primary shard size above recommended ceiling**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | medium | prod, performance |

Primary shards above ~50 GiB recover slowly, push merge memory pressure, and complicate snapshot/restore parallelism. Flag any open index whose average primary shard size (primary_store_bytes divided by primary count) is at or above 50 GiB so operators can plan a rollover or shrink. System indices (dot-prefixed) are excluded — their lifecycle is controlled by the cluster, not the operator.

- **Probe:** `indices`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0 ||
self.all(idx,
  !has(idx.name) || idx.name.startsWith('.') ||
  !has(idx.status) || idx.status != 'open' ||
  !has(idx.primaries) || int(idx.primaries) == 0 ||
  !has(idx.primary_store_bytes) ||
  (int(idx.primary_store_bytes) / int(idx.primaries)) < 50 * 1024 * 1024 * 1024
)
```

**Count expression (CEL):**

```cel
size(self.filter(idx,
  has(idx.name) && !idx.name.startsWith('.') &&
  has(idx.status) && idx.status == 'open' &&
  has(idx.primaries) && int(idx.primaries) > 0 &&
  has(idx.primary_store_bytes) &&
  (int(idx.primary_store_bytes) / int(idx.primaries)) >= 50 * 1024 * 1024 * 1024
))
```

**Message template:** {{count}} index/indices with average primary shard size at or above 50 GiB.

**Remediation:**

- Command: Roll over the index, increase the primary count via shrink/split, or attach an ILM/ISM policy that rolls over before this size is reached
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/size-your-shards.html>
- `esops ops shards`
- `esops index list`
- `esops index rollover`
- `esops index shrink`

---

### `unassigned_shards`

**Cluster has unassigned shards**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch, opensearch | medium | prod, availability |

Unassigned shards mean some primary or replica is not currently allocated — a yellow or red cluster as far as the affected indices are concerned. Surface the count from /_cluster/health so the operator can investigate via /_cluster/allocation/explain.

- **Probe:** `cluster_health`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
!has(self.unassigned_shards) || int(self.unassigned_shards) == 0
```

**Count expression (CEL):**

```cel
has(self.unassigned_shards) ? int(self.unassigned_shards) : 0
```

**Message template:** {{count}} unassigned shard(s) reported by /_cluster/health.

**Remediation:**

- Command: Run /_cluster/allocation/explain on the affected indices to identify why allocation cannot proceed
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-allocation-explain.html>
- `esops ops allocation-explain`
- `esops ops shards`
- `esops ops health`

---

### `zone_awareness`

**Allocation awareness attributes not configured**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | medium | prod, availability |

cluster.routing.allocation.awareness.attributes makes the cluster spread primary and replica copies across the named attribute values (zone, rack, datacenter…). Without it, a multi-node cluster may place every replica of a shard in the same failure domain — defeating the point of the replica. Recommended for any multi-AZ deployment; waiver friendly for single-AZ setups.

- **Probe:** `cluster_settings_full`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
(has(self.persistent) &&
 'cluster.routing.allocation.awareness.attributes' in self.persistent) ||
(has(self.transient) &&
 'cluster.routing.allocation.awareness.attributes' in self.transient)
```

**Count expression (CEL):**

```cel
((has(self.persistent) &&
  'cluster.routing.allocation.awareness.attributes' in self.persistent) ||
 (has(self.transient) &&
  'cluster.routing.allocation.awareness.attributes' in self.transient)) ? 0 : 1
```

**Message template:** cluster.routing.allocation.awareness.attributes is not set.

**Remediation:**

- Command: Set cluster.routing.allocation.awareness.attributes to your zone/rack attribute name and tag each node's node.attr.<name> accordingly
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-cluster.html#shard-allocation-awareness>
- `esops ops settings get`
- `esops ops settings set`
- `esops ops nodes`

---

## security

### `anonymous_access`

**Anonymous access enabled**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| critical | elasticsearch, opensearch | medium | prod, security, framework:cis, framework:soc2, framework:pci |

An anonymous-access posture lets unauthenticated requests through with an implicit identity. ES infers this from xpack.security.authc.anonymous.roles (any roles configured = enabled); OS reads plugins.security.authcz.anonymous_auth_enabled. A non-nil anonymous block on the security audit means the adapter probed and reported the effective state. When security is disabled entirely, this rule passes and security_disabled owns the finding instead — the two rules complement rather than double-fire.

- **Probe:** `security_audit`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
!has(self.status) || !has(self.status.enabled) || self.status.enabled == false ||
!has(self.anonymous) || !has(self.anonymous.enabled) || self.anonymous.enabled == false
```

**Count expression (CEL):**

```cel
(has(self.status) && has(self.status.enabled) && self.status.enabled == true &&
 has(self.anonymous) && has(self.anonymous.enabled) && self.anonymous.enabled == true) ? 1 : 0
```

**Message template:** Cluster is configured to allow anonymous access.

**Remediation:**

- Command: Remove xpack.security.authc.anonymous.roles on Elasticsearch or set plugins.security.authcz.anonymous_auth_enabled=false on OpenSearch and require authentication
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/anonymous-access.html>
- `esops ops audit`

---

### `api_keys_no_expiration`

**Active API keys without expiration**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch | medium | prod, security, framework:cis, framework:soc2 |

Long-lived API keys are an effective bearer credential — once issued, they survive operator turnover, scope changes, and forgotten use cases. Setting an expiration forces a rotation cadence. Flag any active (non-invalidated) API key whose expiration field is empty.

- **Probe:** `security_audit`
- **Affected versions:** 7.x, 8.x, 9.x

**Condition (CEL):**

```cel
!has(self.api_keys) ||
self.api_keys.all(k,
  (has(k.invalidated) && k.invalidated == true) ||
  (has(k.expiration) && k.expiration != '')
)
```

**Count expression (CEL):**

```cel
has(self.api_keys) ?
  size(self.api_keys.filter(k,
    (!has(k.invalidated) || k.invalidated == false) &&
    (!has(k.expiration) || k.expiration == '')
  )) : 0
```

**Message template:** {{count}} active API key(s) have no expiration set.

**Remediation:**

- Command: Re-issue the affected keys with an explicit expiration via the security API and invalidate the originals
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html>
- `esops ops audit`

---

### `audit_logging_enabled`

**Audit logging is disabled**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch, opensearch | medium | prod, security, audit, framework:cis, framework:soc2, framework:pci |

Audit logging records authentication, authorization, and access events. With it off, a security incident has no evidence trail and operators have no way to reconstruct who-did-what. ES enables audit via xpack.security.audit.enabled; OS configures it through the security plugin's audit settings.

- **Probe:** `audit_log`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
has(self.enabled) && self.enabled == true
```

**Count expression (CEL):**

```cel
(has(self.enabled) && self.enabled == true) ? 0 : 1
```

**Message template:** Audit logging is disabled.

**Remediation:**

- Command: Enable xpack.security.audit.enabled on Elasticsearch or configure the OpenSearch security plugin's audit settings, route to an index or logfile sink, and restart the cluster
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/enable-audit-logging.html>
- `esops ops audit`

---

### `default_credentials`

**Built-in user shows no password change**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch | low | prod, security, framework:cis, framework:pci |

The cluster's reserved (built-in) accounts ship with documented default passwords. The cluster's password_changed_at timestamp is the read-only signal that the password has been rotated; empty means either no rotation has happened or the cluster version doesn't surface the field. Restricted to Elasticsearch because the OpenSearch security plugin does not expose this timestamp on any supported version (the field would be empty for every user, false-positiving the whole audit).

- **Probe:** `security_audit`
- **Affected versions:** 7.x, 8.x, 9.x

**Condition (CEL):**

```cel
!has(self.users) ||
self.users.all(u,
  !(has(u.reserved) && u.reserved == true) ||
  !(has(u.enabled) && u.enabled == true) ||
  (has(u.password_changed_at) && u.password_changed_at != '')
)
```

**Count expression (CEL):**

```cel
has(self.users) ?
  size(self.users.filter(u,
    (has(u.reserved) && u.reserved == true) &&
    (has(u.enabled) && u.enabled == true) &&
    (!has(u.password_changed_at) || u.password_changed_at == '')
  )) : 0
```

**Message template:** {{count}} reserved user(s) show no password rotation timestamp.

**Remediation:**

- Command: Rotate the reserved user passwords via the security API; the cluster will populate password_changed_at on the next read
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-change-password.html>
- `esops ops audit`

---

### `deprecated_realms`

**Deprecated authentication realm in use**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | medium | prod, security, framework:cis |

Surfaces realms whose type the cluster's reported version flags as deprecated. Catching a deprecated realm before the next major removes it lets operators plan the migration on their own schedule rather than under upgrade pressure. Disabled realms still count — a disabled-but-present realm needs to come out of the config too, or it lights up the rule again on the next version bump.

- **Probe:** `realms`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
self.all(r, !has(r.deprecated) || r.deprecated == false)
```

**Count expression (CEL):**

```cel
size(self.filter(r, has(r.deprecated) && r.deprecated == true))
```

**Message template:** {{count}} authentication realm(s) use a deprecated type.

**Remediation:**

- Command: Migrate the deprecated realm(s) to a supported type (typically native, ldap, oidc, or saml) and remove the deprecated configuration
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/realms.html>
- `esops ops audit`

---

### `http_tls`

**HTTP TLS not enabled cluster-wide**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| critical | elasticsearch, opensearch | high | prod, security, tls, framework:cis, framework:soc2, framework:pci |

The cluster's HTTP layer is what every external client connects to (esops itself, dashboards, application traffic). Without TLS on that layer, credentials and document content travel in cleartext. Distinct from node-to-node transport TLS surfaced by node_to_node_encryption — both have to be on. The cluster reports HTTPTLSPosture.enabled=true only when every reachable node has HTTP TLS configured. Distinct from tls_transport, which reports the operator's own connection scheme — this rule reports what the cluster says about itself, so a misconfigured node hidden behind a load balancer surfaces here when tls_transport passes.

- **Probe:** `http_tls`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
has(self.enabled) && self.enabled == true
```

**Count expression (CEL):**

```cel
(has(self.enabled) && self.enabled == true) ? 0 : 1
```

**Message template:** HTTP-layer TLS is not enabled cluster-wide.

**Remediation:**

- Command: Configure xpack.security.http.ssl on Elasticsearch (or plugins.security.ssl.http on OpenSearch) on every node and roll the cluster
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/security-basic-setup-https.html>
- `esops ops audit`
- `esops ops nodes`

---

### `license_expiration`

**Elasticsearch licence is expired or expiring soon**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch | low | prod, security |

The cluster's licence drives feature availability — security, machine learning, watcher, and CCR all degrade or disable when the licence expires. The rule fires when the cluster reports a non-active licence (already expired or invalid) or when the installed licence is within 30 days of its expiry, giving an operator enough lead time to run the renewal through whatever procurement loop they need. The probe pre-computes `days_to_expiry` so the condition stays trivial; basic licences never expire and the cluster reports them with no `expires_at`, which the rule treats as a vacuous pass. Elasticsearch-only; OpenSearch has no equivalent commercial-licence surface.

- **Probe:** `license`
- **Affected versions:** 7.x, 8.x, 9.x

**Condition (CEL):**

```cel
(
  !has(self.status) ||
  self.status == 'active'
) &&
(
  !has(self.days_to_expiry) ||
  double(self.days_to_expiry) >= 30.0
)
```

**Message template:** Cluster licence is expired or within 30 days of expiry.

**Remediation:**

- Command: Renew the cluster licence (or downgrade to basic) before the cluster transitions into a degraded feature set; check /_license for the current expiry timestamp
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/update-license.html>

---

### `node_to_node_encryption`

**Node-to-node transport TLS not enabled**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| critical | elasticsearch, opensearch | high | prod, security, tls, framework:cis, framework:soc2, framework:pci |

The cluster's transport channel (port 9300 by default) carries indexing traffic, master-state updates, and inter-node authentication. Without TLS on that channel an attacker on the same network reads documents in flight and can impersonate a cluster member. Distinct from the HTTP-side TLS surfaced by the tls_transport rule — both have to be on. The cluster reports transport_tls_enabled=true only when every reachable node has transport TLS configured.

- **Probe:** `transport_tls`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
has(self.transport_tls_enabled) && self.transport_tls_enabled == true
```

**Count expression (CEL):**

```cel
(has(self.transport_tls_enabled) && self.transport_tls_enabled == true) ? 0 : 1
```

**Message template:** Transport-layer TLS is not enabled cluster-wide.

**Remediation:**

- Command: Configure xpack.security.transport.ssl on Elasticsearch (or plugins.security.ssl.transport on OpenSearch) on every node and roll the cluster
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/security-basic-setup.html>
- `esops ops audit`
- `esops ops nodes`

---

### `permissive_superuser_role`

**Custom role grants cluster-wide all-on-all**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch, opensearch | medium | prod, security, framework:cis, framework:soc2 |

A non-reserved role that grants the `all` cluster privilege over the `*` index pattern is functionally equivalent to the cluster's built-in superuser. Custom roles of this shape mean somebody built a "make this work" role rather than scoping a use case; surface them so the principle of least privilege can be reconsidered.

- **Probe:** `security_audit`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
!has(self.roles) ||
self.roles.all(r,
  (has(r.reserved) && r.reserved == true) ||
  !has(r.cluster_privileges) ||
  !r.cluster_privileges.exists(p, p == 'all') ||
  !has(r.index_patterns) ||
  !r.index_patterns.exists(p, p == '*')
)
```

**Count expression (CEL):**

```cel
has(self.roles) ?
  size(self.roles.filter(r,
    (!has(r.reserved) || r.reserved == false) &&
    has(r.cluster_privileges) &&
    r.cluster_privileges.exists(p, p == 'all') &&
    has(r.index_patterns) &&
    r.index_patterns.exists(p, p == '*')
  )) : 0
```

**Message template:** {{count}} custom role(s) grant cluster=all on indices=*.

**Remediation:**

- Command: Replace the broad role with one scoped to the privileges and index patterns the use case actually needs
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/built-in-roles.html>
- `esops ops audit`

---

### `recent_audit_warnings`

**Recent audit-log warnings present**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | low | prod, security, audit, framework:cis, framework:soc2, framework:pci |

Tails the audit log over the last 24 hours and flags non-empty windows. The probe limits to 1000 rows so a chatty cluster does not blow the rule's evaluation budget. Only metadata is surfaced (timestamp, layer, type) — request bodies and document IDs the audit log records are not exposed to the rule.

- **Probe:** `audit_warnings`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
size(self) == 0
```

**Count expression (CEL):**

```cel
size(self)
```

**Message template:** {{count}} audit-log warning(s) in the last 24 hours.

**Remediation:**

- Command: Triage recent audit warnings in the cluster's audit index or logfile sink and address the underlying authentication or authorization failures
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/audit-event-types.html>
- `esops ops audit`

---

### `script_limits`

**Scripting policy not narrowed**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch, opensearch | medium | prod, security, framework:cis, framework:soc2 |

The default script.allowed_types is "all" — both inline and stored scripts are accepted. In a production cluster, a compromised application credential plus an inline-script privilege escalates to arbitrary code execution on the master. Recommended posture is `script.allowed_types: stored` paired with reviewed stored scripts. Flag any cluster where the setting is unset, leaving the permissive default in place.

- **Probe:** `cluster_settings_full`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
(has(self.persistent) &&
 'script.allowed_types' in self.persistent) ||
(has(self.transient) &&
 'script.allowed_types' in self.transient)
```

**Count expression (CEL):**

```cel
((has(self.persistent) &&
  'script.allowed_types' in self.persistent) ||
 (has(self.transient) &&
  'script.allowed_types' in self.transient)) ? 0 : 1
```

**Message template:** script.allowed_types is not narrowed; inline scripting is enabled by default.

**Remediation:**

- Command: Set persistent script.allowed_types=stored (or =none) via PUT /_cluster/settings, then store any required scripts via /_scripts
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/allowed-script-types-setting.html>
- `esops ops settings get`
- `esops ops settings set`

---

### `security_disabled`

**Cluster security is disabled**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| critical | elasticsearch, opensearch | high | prod, security, framework:cis, framework:soc2, framework:pci |

Reports a cluster where the security model is off entirely — Elasticsearch with xpack.security.enabled=false, or OpenSearch with the security plugin absent. Anonymous read/write to every index is an outright data exposure; this is the highest-priority finding doctor surfaces.

- **Probe:** `security_audit`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
has(self.status) && has(self.status.enabled) && self.status.enabled == true
```

**Count expression (CEL):**

```cel
(has(self.status) && has(self.status.enabled) && self.status.enabled == true) ? 0 : 1
```

**Message template:** Cluster security is disabled — anonymous access is unrestricted.

**Remediation:**

- Command: Enable xpack.security on Elasticsearch (or install the security plugin on OpenSearch), configure realms/roles, and restart the cluster
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/secure-cluster.html>
- `esops ops audit`

---

### `stale_api_keys`

**Long-lived API keys**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch | medium | prod, security, framework:cis, framework:soc2 |

Flags active API keys older than 365 days. Long-lived keys survive operator turnover, scope changes, and forgotten use cases — even when an expiration is set (which the api_keys_no_expiration rule already polices), a one-year-old key is a stale credential by any reasonable rotation cadence. The probe derives age_days at scan time so this rule stays relative to "now"; keys with no surfaced creation timestamp are skipped silently rather than guessed at.

- **Probe:** `api_keys`
- **Affected versions:** 7.x, 8.x, 9.x

**Condition (CEL):**

```cel
self.all(k,
  (has(k.invalidated) && k.invalidated == true) ||
  !has(k.age_days) || k.age_days <= 365
)
```

**Count expression (CEL):**

```cel
size(self.filter(k,
  (!has(k.invalidated) || k.invalidated == false) &&
  has(k.age_days) && k.age_days > 365
))
```

**Message template:** {{count}} active API key(s) older than 365 days.

**Remediation:**

- Command: Rotate the affected API keys via the security API and invalidate the originals; consider scripting the rotation so it runs on a regular cadence
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html>
- `esops ops audit`

---

### `stale_service_tokens`

**Long-lived service-account tokens**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| warn | elasticsearch | medium | prod, security, framework:cis, framework:soc2 |

Flags index-stored service-account tokens (Fleet, APM Server, and similar integration credentials) older than 365 days. The cluster issues these once and they survive until the operator rotates them through the security API. File-realm tokens (declared on disk in service_tokens) are out of scope — the cluster does not timestamp them and rotation requires node access, which is a separate workflow.

- **Probe:** `service_tokens`
- **Affected versions:** 7.x, 8.x, 9.x

**Condition (CEL):**

```cel
self.all(t,
  !has(t.source) || t.source != 'index' ||
  !has(t.age_days) || t.age_days <= 365
)
```

**Count expression (CEL):**

```cel
size(self.filter(t,
  has(t.source) && t.source == 'index' &&
  has(t.age_days) && t.age_days > 365
))
```

**Message template:** {{count}} index-stored service-account token(s) older than 365 days.

**Remediation:**

- Command: Issue new tokens for the affected service accounts via the security API and delete the old credentials once integrations have rolled over
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/service-accounts.html>
- `esops ops audit`

---

### `tls_insecure_skip_verify`

**Cluster context skips TLS verification**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| error | elasticsearch, opensearch | low | prod, security, tls, framework:cis, framework:soc2, framework:pci |

The configured context turns off TLS certificate validation (`insecure: true`). Connections look encrypted but accept any certificate, including a man-in-the-middle's. Acceptable only as a one-shot during initial bootstrap; never as a steady state.

- **Probe:** `security_audit`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
!has(self.tls) || !has(self.tls.insecure_skip_verify) ||
self.tls.insecure_skip_verify == false
```

**Count expression (CEL):**

```cel
(has(self.tls) && has(self.tls.insecure_skip_verify) &&
 self.tls.insecure_skip_verify == true) ? 1 : 0
```

**Message template:** Cluster context has insecure_skip_verify=true; TLS chain is not validated.

**Remediation:**

- Command: Trust the cluster's CA via the context's cacert path and remove `insecure: true`
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/security-basic-setup-https.html>
- `esops config view`

---

### `tls_transport`

**TLS not configured for cluster connection**

| Severity | Dialects | Effort | Tags |
|---|---|---|---|
| critical | elasticsearch, opensearch | medium | prod, security, tls, framework:cis, framework:soc2, framework:pci |

The configured context connects to the cluster over plain HTTP. Credentials, document content, and admin commands all travel in cleartext. The check reads the local TLS posture (scheme + auth knobs) — the cluster cannot tell us whether `insecure: true` was set client-side, so this is reported from the operator's own configuration.

- **Probe:** `security_audit`
- **Affected versions:** 7.x, 8.x, 9.x, 1.x, 2.x, 3.x

**Condition (CEL):**

```cel
has(self.tls) && has(self.tls.scheme) && self.tls.scheme == 'https'
```

**Count expression (CEL):**

```cel
(has(self.tls) && has(self.tls.scheme) && self.tls.scheme == 'https') ? 0 : 1
```

**Message template:** Cluster context is not using HTTPS.

**Remediation:**

- Command: Update the cluster's HTTP layer to use TLS (xpack.security.http.ssl on ES, plugins.security.ssl.http on OS) and switch the context URL to https://
- Doc: <https://www.elastic.co/guide/en/elasticsearch/reference/current/security-basic-setup-https.html>
- `esops ops audit`
- `esops config view`

---

