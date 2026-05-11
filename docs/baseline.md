# Baselines and diff

A baseline records findings from a previous scan. This lets you adopt `esops-doctor` immediately while addressing legacy issues on your own schedule.

`esops-doctor diff` compares two scan reports and highlights regressions, resolutions, and severity changes.

## How baselines work

Findings are matched by the tuple **(rule_id, dialect, target)**.

Use `--baseline PATH` to load a previous scan report:

```bash
# Create baseline
esops-doctor scan --context prod --output sarif > baseline.sarif

# Use it in future scans
esops-doctor scan --context prod --baseline baseline.sarif
```

Baselined findings are shown but do **not** trigger `--fail-on`. They appear in a separate "baselined" section.

## esops-doctor diff

Compares two scan reports (JSON or SARIF):

```bash
esops-doctor diff old.sarif new.sarif
```

**Output sections**
- `added` — new regressions
- `resolved` — fixed findings
- `severity_changed` — severity increased or decreased

**Exit codes**
- `0` — no regressions
- `20` — regressions found (added findings or severity increases)

**Common use cases**
- Pre-commit check: `esops-doctor diff baseline.sarif scan.sarif`
- Refresh baseline after fixes: re-run `scan` and overwrite the baseline file

## Refreshing a baseline

After fixing findings, refresh the baseline:

```bash
esops-doctor scan --context prod --output sarif > baseline.sarif
```

Baselines work across multi-cluster scans and respect dialect boundaries.