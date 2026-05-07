# esops-doctor

Read-only diagnostic linter for self-hosted Elasticsearch and OpenSearch clusters. Think `kube-bench` / `kube-score` but for ES/OS: *"Tell me what's wrong."*

`esops-doctor` is the diagnostic counterpart to [`esops`].(https://github.com/esops-dev/esops-go), `esops` is imperative and may mutate, `esops-doctor` is declarative, opinionated and **never mutates**.

## Read-only by construction

It is read-only based on the import graph, not due to review discipline. If CI detects any internal dependency referencing a mutating API within `esops-go/pkg/client` or directly importing an Elasticsearch / OpenSearch client managed by itself, then the build will fail. Ran `esops-doctor` on production through CI, sans protection tier ritual.

## Installation

Pre-built binary files are available for download with every
[GitHub release](https://github.com/esops-dev/esops-doctor/releases):

- Archive files for `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, and `windows/amd64`.
- Debian (.deb) and RPM packages for Linux.
- Digital signatures and SBOM files (CycloneDX & SPDX) along with the binary.

Extract the downloaded file and move `esops-doctor` somewhere on your `$PATH`.

## Configuring a context

`esops-doctor` reuses the `esops` config file (`~/.config/esops/config.yaml`, or `$ESOPS_CONFIG`) and its `contexts` map. If you have `esops` configured, you have `esops-doctor` configured.

A minimal config:

```yaml
current-context: prod
contexts:
  prod:
    url: https://prod-es.example.internal:9200
    auth:
      type: basic
      username: doctor
      password: ${env:ES_DOCTOR_PASSWORD}
    tls:
      ca_cert: /etc/ssl/certs/internal-ca.pem
  staging:
    url: https://staging-es.example.internal:9200
    auth:
      type: api_key
      api_key: ${file:/etc/esops/staging.apikey}
```

Secret indirection (`${env:...}`, `${file:...}`, `${keyring:...}`) is resolved by `esops-go`. `--context NAME` overrides `current-context`; `--url URL` bypasses the config entirely for one-off probes.

## Quick start

```sh
esops-doctor scan --context prod
esops-doctor scan --profile prod --output sarif > findings.sarif
esops-doctor scan --targets local-es,local-os --output html
esops-doctor explain heap_size
esops-doctor list-rules --tags security
```

Run `esops-doctor --help` and `esops-doctor <command> --help` for the
full flag surface — the help text is the canonical CLI reference.

## Profiles

| Profile     | Intended use                                    |
|-------------|--------------------------------------------------|
| `prod`      | Production scans; promotes hygiene to critical. |
| `staging`   | Pre-prod scans.                                  |
| `dev`       | Local; demotes hygiene findings.                 |
| `ci`        | CI pipelines; deterministic exit codes.          |
| `cis-bench` | CIS-inspired benchmark subset.                   |

## Output formats

`table` (default), `json`, `yaml`, `sarif`, `junit`, `html`. Example of `html` report can be found on [docs/report.html](docs/report.html)

Findings render to stdout; logs and progress render to stderr, so the report is always pipeable.

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

Rules are YAML, evaluated by [CEL](https://github.com/google/cel-spec). Adding a rule is a YAML change, not a Go change. See [docs/rules.md](docs/rules.md) for the authoring workflow and [docs/probes.md](docs/probes.md) for the data shape each probe exposes.

Drop custom rules in `~/.config/esops-doctor/rules.d/` or pass `--rules-dir PATH` to layer them over the embedded catalog.

## Privacy and telemetry

No telemetry from `esops-doctor`. No opt-in, no opt-out, no "crash reports only". There is no SDK sending back telemetry, no OpenTelemetry exporter embedded into the binary code, no check for updates. Every single network connection made by the binary is to the URLs pointing to your cluster.

Probes will fetch metadata about the cluster - settings, mappings, templates, policies, health and stats, auditing metadata. They will not fetch the contents of any user documents. See [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
