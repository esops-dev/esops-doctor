// Package config loads operator configuration. Doctor reuses the esops
// file shape: same ~/.config/esops/config.yaml, same contexts — operators
// who have set up esops do not configure doctor separately.
//
// Only the read-side of the file is parsed here: contexts, current-context,
// and the defaults block that supplies the logger settings. Auth, TLS, and
// secret-indirection handling belong to the cluster-touching code path and
// will be added when probes start consuming esops-go's pkg/client.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Config is the parsed esops configuration file.
type Config struct {
	CurrentContext string             `koanf:"current-context"`
	Defaults       Defaults           `koanf:"defaults"`
	Contexts       map[string]Context `koanf:"contexts"`
}

// Defaults apply to every context unless overridden. Doctor reads
// LogLevel / LogFormat / LogFile to seed the global logger when no flag
// is set, and Output as the fallback for --output. Other fields are kept
// so the parsed shape matches esops's config and a shared file does not
// produce "unknown key" warnings.
type Defaults struct {
	Output    string        `koanf:"output"`
	LogLevel  string        `koanf:"log_level"`
	LogFormat string        `koanf:"log_format"`
	LogFile   string        `koanf:"log_file"`
	Timeout   time.Duration `koanf:"timeout"`
}

// Context describes how to reach a single cluster.
type Context struct {
	URL     string        `koanf:"url"`
	URLs    []string      `koanf:"urls"`
	TLS     TLS           `koanf:"tls"`
	Timeout time.Duration `koanf:"timeout"`
}

// TLS overrides for a context. `insecure` is the last-resort escape hatch.
type TLS struct {
	CACert   string `koanf:"cacert"`
	Insecure bool   `koanf:"insecure"`
}

// Addresses returns the effective list of URLs for the context, preferring
// `urls` over the single `url` when both are set.
func (c Context) Addresses() []string {
	if len(c.URLs) > 0 {
		return c.URLs
	}
	if c.URL != "" {
		return []string{c.URL}
	}
	return nil
}

// Resolve returns the effective config path. If `explicit` is non-empty,
// it is returned unchanged — the caller asked for this specific file.
// Otherwise the standard lookup order is searched and the first existing
// path wins:
//
//  1. $ESOPS_CONFIG                               (env)
//  2. ./esops.yaml                                (per-repo)
//  3. $XDG_CONFIG_HOME/esops/config.yaml          (XDG)
//  4. ~/.config/esops/config.yaml                 (XDG fallback)
//
// $ESOPS_CONFIG must point at an existing file; a missing env-specified
// file is an error rather than a silent fallthrough.
func Resolve(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if env := os.Getenv("ESOPS_CONFIG"); env != "" {
		if _, err := os.Stat(env); err != nil { // #nosec G304,G703 -- ESOPS_CONFIG points at the user's chosen config file
			return "", fmt.Errorf("ESOPS_CONFIG=%q: %w", env, err)
		}
		return env, nil
	}
	candidates := searchPaths()
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no esops config found; searched:\n  %s\npass --config PATH, set ESOPS_CONFIG, or create ~/.config/esops/config.yaml",
		strings.Join(candidates, "\n  "))
}

func searchPaths() []string {
	paths := []string{"esops.yaml"}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		paths = append(paths, filepath.Join(x, "esops", "config.yaml"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".config", "esops", "config.yaml"))
	}
	return paths
}

// Parse reads and unmarshals a config file. No safety checks (file
// permissions, plaintext-secret detection) — those live in esops; doctor
// is read-only and will gain them when the cluster-touching path lands.
func Parse(path string) (Config, error) {
	k := koanf.New(".")
	if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
		return Config{}, fmt.Errorf("loading config %q: %w", path, err)
	}
	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return Config{}, fmt.Errorf("parsing config: %w", err)
	}
	return cfg, nil
}

// LoadDefault resolves the effective config path (honouring `explicit`
// if non-empty, otherwise searching the standard lookup order from
// Resolve) and parses it. Returns the resolved path alongside the parsed
// Config so callers can reference it in messages.
func LoadDefault(explicit string) (Config, string, error) {
	path, err := Resolve(explicit)
	if err != nil {
		return Config{}, "", err
	}
	cfg, err := Parse(path)
	return cfg, path, err
}

// ResolveContext returns the effective Context for `name`, or for
// cfg.CurrentContext if `name` is empty. Defaults are merged in where
// the context hasn't overridden them.
func (cfg Config) ResolveContext(name string) (string, Context, error) {
	if name == "" {
		name = cfg.CurrentContext
	}
	if name == "" {
		return "", Context{}, errors.New("no context specified and no current-context set in config")
	}
	ctx, ok := cfg.Contexts[name]
	if !ok {
		return "", Context{}, fmt.Errorf("context %q not found in config", name)
	}
	if ctx.Timeout == 0 {
		ctx.Timeout = cfg.Defaults.Timeout
	}
	return name, ctx, nil
}
