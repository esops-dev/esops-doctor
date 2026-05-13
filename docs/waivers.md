# Waivers

A waiver is a documented exception: “rule X is allowed to fail because we know about it and here’s why.” Waivers carry a required justification and an optional expiry date so they cannot rot silently.

---

## Creating a waivers file

Create `.esops-doctor.yaml` (or any name) with:

```yaml
waivers:
  - rule_id: api_keys_no_expiration
    justification: legacy ingest keys; rotation tracked in INFRA-4821
    expires_at: 2026-09-30

  - rule_id: deprecated_realms
    justification: kept for analytics-etl bridge; INFRA-4102
```

Doctor looks for waivers in this order:
- `./.esops-doctor.yaml`
- `$XDG_CONFIG_HOME/esops-doctor/waivers.yaml`
- `~/.config/esops-doctor/waivers.yaml`

Or point explicitly: `--waivers /path/to/waivers.yaml`.

---

## Schema

| Field          | Required | Purpose                                      |
|----------------|----------|----------------------------------------------|
| `rule_id`      | yes      | Rule to suppress (or deprecated alias)       |
| `justification`| yes      | Why the exception exists                     |
| `expires_at`   | no       | `YYYY-MM-DD` (end-of-day UTC)                |

A waiver with no `expires_at` is permanent. Expired waivers re-surface the finding with a `[waiver expired YYYY-MM-DD]` prefix and count toward `--fail-on`.

---

## How waivers appear

- **Active** → shown as `waived` with justification visible; ignored by `--fail-on`.
- **Expired** → treated as a normal failure with prefixed message.
- In JSON/YAML/SARIF/JUnit/HTML the suppression metadata is preserved for auditing.

**Common use cases**
- Accept known legacy findings while you migrate
- Silence temporary issues during a rollout
- Force periodic review with `expires_at`

Doctor never mutates your cluster — waivers are purely local.
