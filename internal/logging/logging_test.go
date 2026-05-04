package logging

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want slog.Level
		err  bool
	}{
		{"", slog.LevelInfo, false},
		{"info", slog.LevelInfo, false},
		{"DEBUG", slog.LevelDebug, false},
		{"  warn  ", slog.LevelWarn, false},
		{"warning", slog.LevelWarn, false},
		{"error", slog.LevelError, false},
		{"trace", 0, true},
	}
	for _, c := range cases {
		got, err := parseLevel(c.in)
		if c.err {
			if err == nil {
				t.Errorf("parseLevel(%q): expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseLevel(%q): unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseLevel(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestInitFormats(t *testing.T) {
	for _, format := range []string{"", "text", "TEXT", "json", "JSON"} {
		if err := Init("info", format, ""); err != nil {
			t.Errorf("Init(info, %q, \"\"): unexpected error: %v", format, err)
		}
	}
}

func TestInitRejectsUnknownFormat(t *testing.T) {
	if err := Init("info", "yaml", ""); err == nil {
		t.Error("Init with unknown format: expected error")
	}
}

func TestInitRejectsUnknownLevel(t *testing.T) {
	if err := Init("trace", "text", ""); err == nil {
		t.Error("Init with unknown level: expected error")
	}
}

func TestInitWithLogFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "doctor.log")
	if err := Init("info", "json", path); err != nil {
		t.Fatalf("Init with log file: %v", err)
	}
	Logger().Info("hello", "k", "v")

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Error("log file is empty after a log call")
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("log file mode = %o, want 0600", mode)
	}
}

func TestInitLogFileMissingDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope", "doctor.log")
	if err := Init("info", "text", path); err == nil {
		t.Error("Init with missing parent dir: expected error")
	}
}

func TestLoggerBeforeInit(t *testing.T) {
	if Logger() == nil {
		t.Error("Logger() returned nil before Init")
	}
}

func TestValidLevel(t *testing.T) {
	for _, s := range []string{"", "debug", "info", "WARN", "warning", "error"} {
		if !ValidLevel(s) {
			t.Errorf("ValidLevel(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"trace", "verbose", "fatal"} {
		if ValidLevel(s) {
			t.Errorf("ValidLevel(%q) = true, want false", s)
		}
	}
}

func TestValidFormat(t *testing.T) {
	for _, s := range []string{"", "text", "JSON", "json"} {
		if !ValidFormat(s) {
			t.Errorf("ValidFormat(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"yaml", "ndjson", "xml"} {
		if ValidFormat(s) {
			t.Errorf("ValidFormat(%q) = true, want false", s)
		}
	}
}
