# Authoring rules

Rules are YAML files evaluated by [CEL](https://github.com/google/cel-spec).
Adding a rule does not require a Go change — only a YAML file with a
fixture-based test.

## File location

Core rules live under `rules/<category>/<rule-id>.yaml` and are
embedded into the binary at build time.

Operators can layer additional or overriding rules at runtime via
`--rules-dir PATH`, or in `~/.config/esops-doctor/rules.d/`.

## Rule schema

```yaml
checks:
  - id: heap_size
    name: JVM heap size configuration
    category: resource_sanity
    severity: critical            # info | warn | error | critical
    description: One paragraph on what is checked and why.
    probe: nodes                  # name of a registered probe adapter
    condition: |
      <CEL expression evaluating to bool>
    message: Human-readable summary; supports {{count}} templating.
    remediation:
      command: Concrete `esops` command, if one applies.
      doc_url: https://...
    tags: [prod, performance]
    dialects: [elasticsearch, opensearch]
    affected_versions: ["7.x", "8.x", "9.x", "1.x", "2.x", "3.x"]
    effort: low | medium | high
```

## Stable IDs

Rule IDs are part of the public surface — operator waivers reference
them. Renaming a rule requires keeping the old ID as a deprecation
alias for one minor version.

## Tests

Every rule ships with at least one passing fixture and one failing
fixture. CI fails if a rule lacks a test.

## Probes

`probe:` refers to a probe registered in `internal/probes/`. Adding a
new probe requires a Go change; adding a rule that uses an existing
probe does not. If a rule needs cluster data that no read-only
capability of `esops-go/pkg/client` exposes today, file an upstream
issue — do not reach around the boundary.
