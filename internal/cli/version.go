package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/urfave/cli/v3"

	"github.com/esops-dev/esops-doctor/internal/version"
)

type versionInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Commit      string `json:"commit"`
	Date        string `json:"date"`
	GoVersion   string `json:"go_version"`
	EsopsModule string `json:"esops_module"`
	CGOEnabled  bool   `json:"cgo_enabled"`
}

func collectVersionInfo() versionInfo {
	info := versionInfo{
		Name:        "esops-doctor",
		Version:     version.Version,
		Commit:      version.Commit,
		Date:        version.Date,
		GoVersion:   runtime.Version(),
		EsopsModule: version.EsopsModule,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "CGO_ENABLED" {
				info.CGOEnabled = s.Value == "1"
				break
			}
		}
	}
	return info
}

func versionCommand() *cli.Command {
	return &cli.Command{
		Name:  "version",
		Usage: "Print version information",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "output format: text | json",
				Value:   "text",
			},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			return printVersion(os.Stdout, cmd.String("output"))
		},
	}
}

func printVersion(w io.Writer, format string) error {
	info := collectVersionInfo()
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	case "text", "":
		out := fmt.Sprintf("%s %s\n  commit:    %s\n  built:     %s\n  go:        %s\n  esops-go:  %s\n  cgo:       %v\n",
			info.Name, info.Version, info.Commit, info.Date, info.GoVersion, info.EsopsModule, info.CGOEnabled)
		_, err := io.WriteString(w, out)
		return err
	default:
		return fmt.Errorf("unsupported output format %q (want: text, json)", format)
	}
}
