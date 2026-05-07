# Security policy

## Supported versions

The latest minor release receives security fixes. Older minors are best-effort.

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories on this repository, or email `security@esops.dev`. Do not open public issues for security problems.

We aim to acknowledge receipt within 3 business days and to provide a fix or mitigation within 30 days for high-severity issues.

## Verifying release artifacts

Release artifacts are signed with [cosign](https://github.com/sigstore/cosign) in keyless mode and ship with CycloneDX and SPDX SBOMs. SLSA build provenance is attached to each release. See the GitHub release page for the verification command.

## Telemetry

`esops-doctor` doesn’t send any data, track, or record telemetry. There’s no opt-in, opt-out, anonymous crash reports, or autoupdate ping. The binary doesn’t make any external requests except for the cluster URLs defined by the operator using `--context` or `--url`. There’s no SDK for telemetry or metrics imported within the binary codebase, even OpenTelemetry.

## Read-only by construction

Each cluster operation must pass through the read-only capabilities surface in `esops-go/pkg/client`. Any mutations to capabilities cannot be reached from the import graph; any reference causes CI to fail the build.
A user executing `esops-doctor scan --context prod` need not trust the
project maintainers, as the read-only nature of the program can be verified.

## Data handled

Probe queries *metadata* for the clusters: configurations, mappings,
templates, policies for ILM/ISM, health, node stats, index stats,
snapshot repositories, metadata for auditing, security realms.
Probes do not examine data in documents; this is an explicit non-goal.

The reports include names of clusters, nodes, and indexes and also
include snippets of configuration settings. Consider these report
documents (`findings.sarif`, `report.html`, etc.) to be at the
same sensitivity level as the inventory data.
