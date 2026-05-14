package rulepack

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// ManifestFileName is the canonical name of the manifest inside a pack
// directory. Operators reading a pack tree see this file first; the
// fixed name lets the operator's cosign verification step target one
// well-known path.
const ManifestFileName = "MANIFEST.yaml"

// ManifestVersion is the schema version embedded in every manifest.
// Bumping it is a deliberate, breaking change — verifiers refuse to
// load a pack whose manifest declares a version this binary does not
// recognise.
const ManifestVersion = 1

// HashAlgorithm is the only hash algorithm the manifest schema
// accepts. Sticking to one keeps the verification surface small and
// makes a future migration explicit (operators rotate manifests rather
// than discovering a silent algorithm switch).
const HashAlgorithm = "sha256"

// Manifest is the integrity ledger that lives at the root of a rule
// pack. Files lists every rule YAML in the pack, keyed by the
// pack-relative path with forward-slash separators, with the
// associated hash. Created records the pack author's free-form
// description — surfaced in logs so operators can confirm what they
// loaded without re-reading the file.
type Manifest struct {
	Version     int               `yaml:"version"`
	Algorithm   string            `yaml:"algorithm"`
	Name        string            `yaml:"name,omitempty"`
	Description string            `yaml:"description,omitempty"`
	Files       map[string]string `yaml:"files"`
}

// Verify reads packDir/MANIFEST.yaml and asserts every listed file
// hashes to the recorded value. Files not in the manifest are reported
// — a pack may not ship arbitrary extra YAML alongside the listed
// rules, because an unsigned file dropped next to a signed manifest
// is exactly the threat the manifest guards against.
//
// On success Verify returns the manifest. Any mismatch, missing file,
// or unlisted extra file fails the whole pack: partial trust is worse
// than no trust here.
func Verify(packDir string) (*Manifest, error) {
	manifestPath := filepath.Join(packDir, ManifestFileName)
	data, err := os.ReadFile(manifestPath) // #nosec G304 -- operator-supplied via --rules-pack
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("rule pack %s: missing %s — point --rules-pack at the directory holding the manifest", packDir, ManifestFileName)
		}
		return nil, fmt.Errorf("reading manifest %s: %w", manifestPath, err)
	}
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest %s: %w", manifestPath, err)
	}
	if m.Version != ManifestVersion {
		return nil, fmt.Errorf("manifest %s declares version %d; this binary only supports version %d", manifestPath, m.Version, ManifestVersion)
	}
	if !strings.EqualFold(m.Algorithm, HashAlgorithm) {
		return nil, fmt.Errorf("manifest %s declares algorithm %q; this binary only supports %q", manifestPath, m.Algorithm, HashAlgorithm)
	}
	if len(m.Files) == 0 {
		return nil, fmt.Errorf("manifest %s lists no files", manifestPath)
	}

	if err := verifyManifestEntries(packDir, &m); err != nil {
		return nil, err
	}
	if err := verifyNoUnlistedYAML(packDir, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// verifyManifestEntries walks every entry in the manifest, asserts the
// file exists, and confirms its hash matches the recorded value. The
// walk is deterministic (sorted by path) so the first failure an
// operator sees is the lexicographically earliest mismatch — easier to
// reproduce than "whichever map iteration ordered first".
func verifyManifestEntries(packDir string, m *Manifest) error {
	paths := make([]string, 0, len(m.Files))
	for p := range m.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, rel := range paths {
		clean, err := sanitisePath(rel)
		if err != nil {
			return fmt.Errorf("manifest entry %q: %w", rel, err)
		}
		full := filepath.Join(packDir, clean)
		got, err := hashFile(full)
		if err != nil {
			return fmt.Errorf("hashing %s: %w", clean, err)
		}
		want := strings.ToLower(strings.TrimSpace(m.Files[rel]))
		if got != want {
			return fmt.Errorf("hash mismatch for %s: manifest=%s actual=%s", clean, want, got)
		}
	}
	return nil
}

// verifyNoUnlistedYAML rejects packs that ship YAML files not named in
// the manifest. The threat model is "attacker drops an extra rule
// alongside a signed manifest"; allowing unsigned YAML to be loaded
// from the pack defeats the manifest's purpose.
//
// Non-YAML files (LICENSE, README, signature side-cars) are ignored —
// the manifest does not need to enumerate documentation. The cosign
// `.sig` and `.pem` artefacts a pack author ships alongside
// MANIFEST.yaml therefore pass through silently.
func verifyNoUnlistedYAML(packDir string, m *Manifest) error {
	want := make(map[string]struct{}, len(m.Files))
	for p := range m.Files {
		clean, err := sanitisePath(p)
		if err != nil {
			return fmt.Errorf("manifest entry %q: %w", p, err)
		}
		want[filepath.ToSlash(clean)] = struct{}{}
	}
	var unlisted []string
	err := filepath.WalkDir(packDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if base == ManifestFileName {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(base), ".yaml") {
			return nil
		}
		rel, err := filepath.Rel(packDir, path)
		if err != nil {
			return err
		}
		if _, ok := want[filepath.ToSlash(rel)]; !ok {
			unlisted = append(unlisted, rel)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(unlisted) > 0 {
		sort.Strings(unlisted)
		return fmt.Errorf("rule pack %s: unlisted YAML files (would bypass the manifest): %s",
			packDir, strings.Join(unlisted, ", "))
	}
	return nil
}

// Create builds a manifest from the contents of packDir: every *.yaml
// file gets a sha256 entry, sorted by path. An existing MANIFEST.yaml
// is skipped — Create overwrites it, but the existing manifest's own
// hash is not chained in.
//
// name and description are stored verbatim for human consumption.
// Returns the manifest and a sorted slice of the files it covered.
func Create(packDir, name, description string) (*Manifest, []string, error) {
	if info, err := os.Stat(packDir); err != nil {
		return nil, nil, fmt.Errorf("rules-pack dir %q: %w", packDir, err)
	} else if !info.IsDir() {
		return nil, nil, fmt.Errorf("rules-pack dir %q: not a directory", packDir)
	}
	files := map[string]string{}
	var covered []string
	err := filepath.WalkDir(packDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if base == ManifestFileName {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(base), ".yaml") {
			return nil
		}
		rel, err := filepath.Rel(packDir, path)
		if err != nil {
			return err
		}
		h, err := hashFile(path)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		files[key] = h
		covered = append(covered, key)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if len(files) == 0 {
		return nil, nil, fmt.Errorf("rules-pack dir %s: contains no rule YAML files", packDir)
	}
	sort.Strings(covered)
	return &Manifest{
		Version:     ManifestVersion,
		Algorithm:   HashAlgorithm,
		Name:        name,
		Description: description,
		Files:       files,
	}, covered, nil
}

// WriteManifest serialises m to packDir/MANIFEST.yaml. The on-disk file
// is sorted by path (yaml.v3 emits map keys in declaration order, so
// we write through an ordered helper structure) so successive invocations
// produce byte-identical output for unchanged inputs — what cosign and
// the diff between two packs ultimately want.
func WriteManifest(packDir string, m *Manifest) error {
	ordered := orderedManifest{
		Version:     m.Version,
		Algorithm:   m.Algorithm,
		Name:        m.Name,
		Description: m.Description,
	}
	keys := make([]string, 0, len(m.Files))
	for k := range m.Files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered.Files.Kind = yaml.MappingNode
	for _, k := range keys {
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: k}
		valNode := &yaml.Node{Kind: yaml.ScalarNode, Value: m.Files[k]}
		ordered.Files.Content = append(ordered.Files.Content, keyNode, valNode)
	}
	out, err := yaml.Marshal(ordered)
	if err != nil {
		return fmt.Errorf("marshalling manifest: %w", err)
	}
	target := filepath.Join(packDir, ManifestFileName)
	return os.WriteFile(target, out, 0o644) // #nosec G306 -- operator-shared file
}

// orderedManifest mirrors Manifest but stores Files as a yaml.Node so
// we can serialise the entries in deterministic sort order. Manifest
// itself uses a map for ergonomic in-memory access; the on-disk shape
// needs the explicit ordering for byte-stable signatures.
type orderedManifest struct {
	Version     int       `yaml:"version"`
	Algorithm   string    `yaml:"algorithm"`
	Name        string    `yaml:"name,omitempty"`
	Description string    `yaml:"description,omitempty"`
	Files       yaml.Node `yaml:"files"`
}

// sanitisePath rejects manifest entries that escape the pack root
// (".." segments, absolute paths). Filepath separators are normalised
// to the host's so callers can join cleanly against packDir.
func sanitisePath(rel string) (string, error) {
	clean := filepath.Clean(rel)
	if filepath.IsAbs(clean) {
		return "", fmt.Errorf("absolute path not allowed in manifest entries")
	}
	if strings.HasPrefix(clean, "..") || strings.Contains(clean, string(filepath.Separator)+"..") {
		return "", fmt.Errorf("parent-directory references not allowed in manifest entries")
	}
	return clean, nil
}

// hashFile returns the lower-case hex sha256 of path. Used by both the
// create and verify paths so an integrity check is a string compare.
// io.Copy buffers internally and surfaces any non-EOF read error — a
// hand-rolled read loop here was silently swallowing them.
func hashFile(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- pack-internal path already sanitised
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
