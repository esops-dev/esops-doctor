# Authoring rules

A doctor rule is a YAML file + a fixture. No Go code required — the engine compiles your CEL expression at startup and evaluates it against live probe data.

See [probes.md](probes.md) for the shape of `self` in your CEL expression.

## TL;DR workflow

1. Choose a probe from [probes.md](probes.md).
2. Create `rules/<category>/<rule-id>.yaml`.
3. Add a fixture at `testdata/rule_fixtures/<rule-id>.yaml` (one pass + one fail case).
4. Validate:
   ```bash
   go run ./cmd/esops-doctor validate-rules
   go test ./internal/engine/...
   ```
5. Smoke test:
   ```bash
   go run ./cmd/esops-doctor --context <ctx> scan --rule-id <id>
   ```

Custom rules can also be dropped into `~/.config/esops-doctor/rules.d/` or `--rules-dir`.

---

## Rule schema

```yaml
checks:
  - id: heap_size                    # ^[a-z][a-z0-9_]*$
    name: JVM heap size configuration
    category: resource_sanity
    severity: critical               # info | warn | error | critical
    description: >-
      JVM heap should be ~50% of RAM and ≤31 GiB for compressed pointers.
    probe: node_stats                # see probes.md
    condition: |                     # CEL — rule passes when true
      size(self) == 0 ||
      self.all(node, int(node.jvm.heap.max_bytes) <= 31 * 1024 * 1024 * 1024)
    message: Heap size misconfigured on {{count}} nodes.
    remediation:
      command: Update JVM options and restart nodes
    dialects: [elasticsearch, opensearch]
```

**Key fields**
- `id` — unique, used for waivers and filtering.
- `severity` — controls `--fail-on` threshold (default: `error`).
- `condition` — CEL expression returning `bool`.
- `count_expression` (optional) — CEL returning `int` for `{{count}}` in message.
- `dialects` — at least one of `elasticsearch` or `opensearch`.

---

## CEL gotchas

- Numbers arrive as `float64` → use `int(...)` for comparisons.
- Optional fields: guard with `has(field)` or `!has(...) || …`.
- Empty list = pass for most rules: `size(self) == 0 || …`.
- Cluster settings are often strings: `string(self.persistent['key']) == "true"`.
- `has()` works only on dotted paths; use `'key' in map` for map keys.

---

## Fixture file

```yaml
rule: heap_size
cases:
  - name: good 8 GiB heap on 32 GiB host
    expect: pass
    data:
      - name: n1
        jvm: { heap: { max_bytes: 8589934592 } }
        os: { total_physical_memory_bytes: 34359738368 }
  - name: 64 GiB heap (too big)
    expect: fail
    data: […]
```

At least one `pass` and one `fail` case required.

---

## Validating locally

```bash
# Schema + CEL compile
go run ./cmd/esops-doctor validate-rules

# Run all fixtures
go test ./internal/engine/...

# Real-cluster smoke test
go run ./cmd/esops-doctor --context <ctx> scan --rule-id <id>
```

---

## Missing data?

If a probe doesn’t expose what you need:
1. Check [probes.md](probes.md) first.
2. Open an issue in `esops-go` describing the required read-only capability.

Do **not** reach around the client or modify existing probe shapes — this keeps doctor safe for production.

Core rules are embedded at build time. Custom rules use the exact same schema.
