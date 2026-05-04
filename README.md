# esops-doctor

Read-only diagnostic linter for self-managed Elasticsearch and OpenSearch
clusters. Think `kube-bench` / `kube-score`, but for ES/OS. *"Tell me
what's wrong."*

`esops-doctor` is the diagnostic counterpart to
[`esops`](https://github.com/esops-dev/esops-go). Where `esops` is
imperative and may mutate, `esops-doctor` is declarative, opinionated,
and **never mutates**.

## Read-only by construction

The tool is read-only as a property of its import graph, not by review
discipline. CI fails the build if any internal package references a
mutating capability from `esops-go/pkg/client`, or imports a
self-managed Elasticsearch / OpenSearch client directly. Run
`esops-doctor` against production from CI without protection-tier
ceremony.

## Installation

```sh
# Homebrew
brew install esops-dev/tap/esops-doctor

# Go
go install github.com/esops-dev/esops-doctor/cmd/esops-doctor@latest

# Linux packages (deb / rpm) and signed archives are attached to each
# GitHub release.
```

## Quick start

```sh
esops-doctor scan --context prod
esops-doctor scan --profile prod --output sarif > findings.sarif
esops-doctor explain heap_size
esops-doctor list-rules --tags security
```

`esops-doctor` reuses the `esops` config file (`~/.config/esops/config.yaml`)
and contexts. If you have `esops` configured, you have `esops-doctor`
configured.

## Profiles

| Profile     | Intended use                                    |
|-------------|--------------------------------------------------|
| `prod`      | Production scans; promotes hygiene to critical. |
| `staging`   | Pre-prod scans.                                  |
| `dev`       | Local; demotes hygiene findings.                 |
| `ci`        | CI pipelines; deterministic exit codes.          |
| `cis-bench` | CIS-inspired benchmark subset.                   |

## Output formats

`table` (default), `json`, `yaml`, `sarif`, `junit`, `html`.

Findings render to stdout; logs and progress render to stderr, so the
report is always pipeable.

## Exit codes

| Code | Meaning                                                                |
|------|------------------------------------------------------------------------|
| 0    | All findings below `--fail-on` threshold                               |
| 1    | Generic error                                                          |
| 2    | Usage error                                                            |
| 3    | Cluster unreachable                                                    |
| 4    | Authentication failed                                                  |
| 5    | Authorization failed                                                   |
| 10   | Endpoint reachable but not recognised as Elasticsearch or OpenSearch   |
| 20   | Findings ≥ `--fail-on` threshold (the normal CI failure)               |
| 21   | Rule catalog failed to load or validate                                |
| 130  | Interrupted (SIGINT)                                                   |

## Rules

Rules are YAML, evaluated by [CEL](https://github.com/google/cel-spec).
Adding a rule is a YAML change, not a Go change. See [docs/rules.md](docs/rules.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
