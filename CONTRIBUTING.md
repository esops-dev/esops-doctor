# Contributing

Thank you for taking the time to contribute.

## Ground rules

- **Read-only by construction.** No PR may add a direct import of
  `github.com/elastic/go-elasticsearch/...`,
  `github.com/opensearch-project/opensearch-go/...`, or any mutating
  capability from `github.com/esops-dev/esops-go/pkg/client`. CI
  enforces this; do not work around it.
- **Rules are data, not code.** Where possible, contribute new
  diagnostics as YAML rules under `rules/<category>/`, not Go.
- **Every rule has tests.** At least one passing fixture and one
  failing fixture per rule. CI fails otherwise.
- **No telemetry, ever.** Not opt-in, not opt-out, not "crash reports
  only." This includes OpenTelemetry.

## Workflow

1. Open an issue describing the rule, bug, or feature.
2. Fork, branch, commit, push.
3. Open a pull request against `main`. Fill out the PR template.
4. CI must pass: tests, lint, `govulncheck`, import-graph guard,
   binary-size budget.

## Adding a rule

See [docs/rules.md](docs/rules.md).

## Adding a probe

Probes live in `internal/probes/` and are the only packages permitted
to import `esops-go/pkg/client`. Each probe is a thin adapter over a
single read-only capability and returns plain data structures. Register
the probe by name with the engine.

## Local development

```sh
make build
make test
make lint
make vuln
make bin-size       # check the stripped binary stays under budget
```

Integration tests use `testcontainers-go` and are gated by the
`integration` build tag.

## Shell completions

Pre-generated completion scripts live in `completions/` and ship in
the release archives and `.deb`/`.rpm` packages. To install from a
local checkout:

```sh
# bash
sudo install -m 0644 completions/esops-doctor.bash \
    /usr/share/bash-completion/completions/esops-doctor

# zsh — drop on $fpath, e.g.
sudo install -m 0644 completions/_esops-doctor /usr/share/zsh/site-functions/

# fish
install -m 0644 completions/esops-doctor.fish \
    ~/.config/fish/completions/esops-doctor.fish
```

The binary also responds to `esops-doctor completion bash|zsh` for
on-the-fly generation. `completion fish` is unsafe — see the note in
`completions/esops-doctor.fish` for why the static file is canonical.

## License

By contributing, you agree your work is licensed under the Apache
License, Version 2.0.
