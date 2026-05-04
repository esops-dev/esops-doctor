# Security policy

## Supported versions

The latest minor release receives security fixes. Older minors are
best-effort.

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories
on this repository, or email `security@esops.dev`. Do not open public
issues for security problems.

We aim to acknowledge receipt within 3 business days and to provide a
fix or mitigation within 30 days for high-severity issues.

## Verifying release artifacts

Release artifacts are signed with [cosign](https://github.com/sigstore/cosign)
in keyless mode and ship with CycloneDX and SPDX SBOMs. SLSA build
provenance is attached to each release. See the GitHub release page
for the verification command.
