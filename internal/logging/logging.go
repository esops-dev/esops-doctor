// Package logging is the process-wide slog facade. Init sets the
// process-wide logger from --log-level / --log-format / --log-file flag
// values; Logger returns it. Keeping this in one place means every
// command picks up flag changes without plumbing a *slog.Logger through
// every call.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

var (
	mu     sync.RWMutex
	logger = slog.New(slog.NewTextHandler(io.Discard, nil))
)

// Init configures the process-wide logger from --log-level / --log-format
// / --log-file values. Empty logFile keeps the default destination of
// stderr so stdout stays reserved for the requested data — the output
// contract is that stdout only ever carries the data the user asked for,
// and everything else (progress, logs, errors) lands on stderr or in an
// explicit log file. A non-empty logFile is opened in append mode with
// 0600 permissions — log lines commonly include context/cluster names,
// and there's no reason for other system users to read them.
func Init(level, format, logFile string) error {
	lvl, err := parseLevel(level)
	if err != nil {
		return err
	}
	opts := &slog.HandlerOptions{Level: lvl}

	w, err := resolveWriter(logFile)
	if err != nil {
		return err
	}

	var h slog.Handler
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text":
		h = slog.NewTextHandler(w, opts)
	case "json":
		h = slog.NewJSONHandler(w, opts)
	default:
		return fmt.Errorf("unknown log format %q (supported: text, json)", format)
	}

	mu.Lock()
	logger = slog.New(h)
	mu.Unlock()
	return nil
}

// resolveWriter returns os.Stderr when path is empty, otherwise opens
// (creating if needed) the file in append mode with 0600 permissions.
// The parent directory must already exist; creating it implicitly would
// silently hide typos in --log-file.
func resolveWriter(path string) (io.Writer, error) {
	if path == "" {
		return os.Stderr, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- user-supplied via --log-file
	if err != nil {
		return nil, fmt.Errorf("opening log file %q: %w", path, err)
	}
	return f, nil
}

// Logger returns the current process-wide logger. Safe to call before
// Init: returns a logger that discards everything.
func Logger() *slog.Logger {
	mu.RLock()
	defer mu.RUnlock()
	return logger
}

// ValidLevel reports whether s is a recognised --log-level value. Used
// by the flag Validator so bad values fail at flag-parse time with a
// usage error, before any subcommand action runs.
func ValidLevel(s string) bool {
	_, err := parseLevel(s)
	return err == nil
}

// ValidFormat reports whether s is a recognised --log-format value.
func ValidFormat(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "text", "json":
		return true
	}
	return false
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q (supported: debug, info, warn, error)", s)
	}
}
