# Signed rule packs

A **rule pack** is a directory of rule YAML files plus a `MANIFEST.yaml` that records the SHA-256 hash of every shipped rule. Doctor verifies the manifest at load time when an operator points it at the pack with `--rules-pack PATH`. Combined with a cosign signature on the manifest, this gives a downstream operator a supply-chain story for consuming someone else's catalog.

The integrity check (manifest hashes vs. files) lives inside doctor; the **trust** check (who signed the manifest) lives in cosign. Doctor never imports the sigstore SDK — see [CLAUDE.md §4](../CLAUDE.md) for the dependency budget — so the cosign step is an operator-side wrap around the doctor invocation.

---

## Pack layout

```
my-rules-pack/
├── MANIFEST.yaml          # sha256 of every *.yaml below, signed externally
├── MANIFEST.yaml.sig      # cosign signature (operator verifies this)
├── MANIFEST.yaml.pem      # cosign certificate (keyless flow)
├── extra-rule.yaml
└── compliance/
    └── pci-stricter.yaml
```

Only `MANIFEST.yaml` and the listed rule YAMLs are integrity-checked. `*.sig` / `*.pem` side-cars and non-YAML documentation pass through untouched.

### Manifest shape

```yaml
version: 1
algorithm: sha256
name: acme-prod-rules
description: ACME's production-tightened rule overlay
files:
  compliance/pci-stricter.yaml: 1f3a…
  extra-rule.yaml: 9c4b…
```

- `version: 1` is the only supported version today.
- `algorithm: sha256` is the only supported algorithm. A future migration will bump both fields together.
- Paths are pack-relative, forward-slash. Absolute paths and `..` segments are refused.
- Every YAML file under the pack root must appear in `files:`; an unlisted YAML next to a signed manifest would silently bypass verification, so doctor rejects the whole pack.

---

## Pack author workflow

```bash
# 1. Lay out the rules under a single directory.
mkdir -p my-rules-pack/compliance
cp ../path/to/extra-rule.yaml my-rules-pack/
cp ../path/to/pci-stricter.yaml my-rules-pack/compliance/

# 2. Write the manifest. (Re-run after every edit.)
esops-doctor rules-pack create my-rules-pack \
    --name "acme-prod-rules" \
    --description "ACME's production-tightened rule overlay"

# 3. Sign the manifest with cosign keyless.
cosign sign-blob \
    --output-signature my-rules-pack/MANIFEST.yaml.sig \
    --output-certificate my-rules-pack/MANIFEST.yaml.pem \
    my-rules-pack/MANIFEST.yaml

# 4. Distribute the directory (tar it, publish to a registry, drop it
#    into the consuming repo as a submodule — your choice).
```

The doctor binary never invokes cosign. The author's signing tooling is theirs to pick.

---

## Operator workflow

```bash
# 1. Verify the manifest's cosign signature. This is the trust root —
#    if it fails, do NOT proceed.
cosign verify-blob \
    --certificate          my-rules-pack/MANIFEST.yaml.pem \
    --signature            my-rules-pack/MANIFEST.yaml.sig \
    --certificate-identity 'release-bot@acme.example' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    my-rules-pack/MANIFEST.yaml

# 2. (Optional) Re-verify the manifest matches the files locally. The
#    --rules-pack flag does this automatically, but pre-scan verification
#    surfaces tampering before the scan path runs anything else.
esops-doctor rules-pack verify my-rules-pack

# 3. Run a scan with the pack layered over the embedded catalog.
esops-doctor --context prod scan --rules-pack ./my-rules-pack
```

`scan --rules-pack PATH` calls `rules-pack verify` internally before loading; a hash mismatch or unlisted YAML aborts the scan with the same exit-21 catalog error an invalid `--rules-dir` produces.

---

## Threat model

| Threat                              | Mitigation                                                   |
|-------------------------------------|--------------------------------------------------------------|
| Tampered rule YAML                  | Manifest hash check (`rules-pack verify` / `--rules-pack`)   |
| Unsigned manifest accepted          | Operator's `cosign verify-blob` step before pointing doctor  |
| Extra YAML smuggled into pack       | Doctor rejects unlisted YAML files alongside the manifest    |
| Algorithm downgrade                 | Only sha256 accepted; manifest version pinned at `1`         |
| Pack-internal symlink escape        | `..` and absolute paths refused in manifest entries          |
| Doctor compromise                   | Out of scope — verify the doctor binary's own cosign signature against the release |

---

## Layering and overrides

Pack rules layer **after** `--rules-dir` and **before** the user `rules.d` directory in the same merge order described in [rules.md](rules.md):

```
embedded core → --rules-dir → --rules-pack → ~/.config/esops-doctor/rules.d/
```

A same-id collision shadows the lower layer and logs the override path, so an operator can locally pin a single rule from a pack without forking the pack.
