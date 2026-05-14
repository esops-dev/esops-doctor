package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/esops-dev/esops-doctor/internal/exit"
	"github.com/esops-dev/esops-doctor/internal/logging"
	"github.com/esops-dev/esops-doctor/internal/rulepack"
	"github.com/esops-dev/esops-doctor/internal/rules"
)

// rulesPackCommand groups the supply-chain-hardened entry points for
// third-party rule catalogs: `verify` runs the manifest check without
// loading, `create` writes a fresh MANIFEST.yaml.
//
// The cosign sign/verify step on MANIFEST.yaml is intentionally out of
// scope: doctor never imports a sigstore SDK (dep budget) and pulls
// the trust root from the operator running `cosign verify-blob`
// against the manifest before pointing doctor at the pack. See
// docs/rules-packs.md.
func rulesPackCommand() *cli.Command {
	return &cli.Command{
		Name:  "rules-pack",
		Usage: "Inspect or build a signed rule pack (manifest + cosign-verified by the operator)",
		Description: "A rule pack is a directory of rule YAMLs plus a MANIFEST.yaml that\n" +
			"records each file's SHA-256 hash. The manifest is intended to be\n" +
			"cosign-signed by the pack author; the operator runs `cosign\n" +
			"verify-blob` against MANIFEST.yaml before pointing doctor at the\n" +
			"pack with --rules-pack PATH.\n\n" +
			"This command exposes the data-integrity side of the workflow:\n" +
			"`verify` re-hashes every listed file and rejects packs that\n" +
			"diverge; `create` writes a fresh manifest covering every *.yaml\n" +
			"under PATH (excluding MANIFEST.yaml itself).",
		Commands: []*cli.Command{
			rulesPackVerifyCommand(),
			rulesPackCreateCommand(),
		},
	}
}

func rulesPackVerifyCommand() *cli.Command {
	return &cli.Command{
		Name:      "verify",
		Usage:     "Verify a pack's MANIFEST.yaml hashes match every shipped rule file",
		ArgsUsage: "PATH",
		Description: "Reads PATH/MANIFEST.yaml and asserts every listed file hashes to the\n" +
			"recorded value. Fails on any mismatch, on missing files, and on YAML\n" +
			"files in the pack that are not listed in the manifest — an unlisted\n" +
			"file would bypass the integrity check, which is exactly the threat\n" +
			"the manifest guards against.\n\n" +
			"Pair this with `cosign verify-blob` against PATH/MANIFEST.yaml: the\n" +
			"cosign step proves who signed the manifest; this step proves the\n" +
			"manifest still matches the pack.",
		Action: func(_ context.Context, cmd *cli.Command) error {
			return runRulesPackVerify(cmd, cmdWriter(cmd))
		},
	}
}

func runRulesPackVerify(cmd *cli.Command, stdout io.Writer) error {
	if cmd.NArg() != 1 {
		return exit.Usage("rules-pack verify requires exactly one PATH argument; got %d", cmd.NArg())
	}
	path := strings.TrimSpace(cmd.Args().First())
	if path == "" {
		return exit.Usage("rules-pack verify requires a non-empty PATH argument")
	}
	m, err := rulepack.Verify(path)
	if err != nil {
		return exit.Catalog("%s", err)
	}
	if _, err := fmt.Fprintf(stdout, "OK: pack %s verified (%d file(s)", path, len(m.Files)); err != nil {
		return err
	}
	if m.Name != "" {
		if _, err := fmt.Fprintf(stdout, ", name=%q", m.Name); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(stdout, ")"); err != nil {
		return err
	}
	return nil
}

func rulesPackCreateCommand() *cli.Command {
	return &cli.Command{
		Name:      "create",
		Usage:     "Write a fresh MANIFEST.yaml for a directory of rule YAMLs",
		ArgsUsage: "PATH",
		Description: "Walks PATH for *.yaml files (excluding MANIFEST.yaml) and writes\n" +
			"PATH/MANIFEST.yaml carrying a sha256 hash per file. After running\n" +
			"this command, sign the manifest with `cosign sign-blob` so\n" +
			"downstream operators have a trust root for the pack.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "name",
				Usage: "Free-form pack name written into the manifest (e.g. acme-prod-rules)",
			},
			&cli.StringFlag{
				Name:  "description",
				Usage: "Free-form pack description written into the manifest",
			},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			return runRulesPackCreate(cmd, cmdWriter(cmd))
		},
	}
}

func runRulesPackCreate(cmd *cli.Command, stdout io.Writer) error {
	if cmd.NArg() != 1 {
		return exit.Usage("rules-pack create requires exactly one PATH argument; got %d", cmd.NArg())
	}
	path := strings.TrimSpace(cmd.Args().First())
	if path == "" {
		return exit.Usage("rules-pack create requires a non-empty PATH argument")
	}
	m, covered, err := rulepack.Create(path, cmd.String("name"), cmd.String("description"))
	if err != nil {
		return exit.Catalog("%s", err)
	}
	if err := rulepack.WriteManifest(path, m); err != nil {
		return exit.Catalog("writing manifest: %s", err)
	}
	if _, err := fmt.Fprintf(stdout, "wrote %s/%s (%d file(s) covered)\n", path, rulepack.ManifestFileName, len(covered)); err != nil {
		return err
	}
	for _, p := range covered {
		if _, err := fmt.Fprintf(stdout, "  - %s\n", p); err != nil {
			return err
		}
	}
	return nil
}

// loadRulesPack loads a verified rule pack and returns its rules
// catalog. Used by callers (scan, list-rules, validate-rules) that
// honour --rules-pack PATH alongside the existing --rules-dir layer:
// the pack contents are appended to the embedded catalog with the same
// merge-with-override semantics, after the integrity check passes.
//
// A failed manifest verification short-circuits before any rule YAML is
// parsed — the trust boundary lives at the manifest, so we never feed a
// tampered file into the loader.
func loadRulesPack(packDir string) (*rules.Catalog, error) {
	m, err := rulepack.Verify(packDir)
	if err != nil {
		return nil, exit.Catalog("%s", err)
	}
	logging.Logger().Info("doctor.rules_pack.verified",
		"path", packDir,
		"name", m.Name,
		"files", len(m.Files))
	cat, err := rules.LoadDir(packDir)
	if err != nil {
		return nil, exit.Catalog("loading rules from pack %s: %s", packDir, err)
	}
	return cat, nil
}
