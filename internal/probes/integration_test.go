//go:build integration

// Integration tests for the probe layer. Build-tag-gated so a default
// `go test ./...` stays unit-only — Docker is required to run these.
//
// Run locally:
//
//	go test -tags integration -v -count=1 ./internal/probes/...
//
// Each test in this file spins up a real cluster via testcontainers,
// connects through probes.Connect, and sweeps every Known() probe so
// a regression in a single adapter (or a missing dispatch arm) fails
// against actual cluster wire output instead of hand-rolled fakes.
//
// Cross-dialect probes (ilm_state on OS, ism_state on ES,
// deprecation_log on OS) must surface as engine.ErrProbeNotApplicable
// — the test asserts that explicitly so a future change that lets one
// of them mistakenly succeed (or collapse to ErrProbeNotFound) is
// caught.
package probes

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/esops-dev/esops-go/pkg/config"

	tcgo "github.com/testcontainers/testcontainers-go"
	tcwait "github.com/testcontainers/testcontainers-go/wait"

	"github.com/esops-dev/esops-doctor/internal/engine"
)

// Pinned versions for the fast-path matrix per CLAUDE.md §11. Override
// via env (ESOPS_DOCTOR_TEST_ES_IMAGE / ESOPS_DOCTOR_TEST_OS_IMAGE) to
// extend to ES 7.17 / 8.x / OS 1.3 / 2.x in nightly runs without
// touching the test source.
const (
	defaultESImage = "docker.elastic.co/elasticsearch/elasticsearch:9.0.0"
	defaultOSImage = "opensearchproject/opensearch:2.18.0"

	clusterStartTimeout = 3 * time.Minute
	probeCallTimeout    = 30 * time.Second
)

// notApplicableOnES is the set of probes whose upstream adapter for
// Elasticsearch returns client.ErrUnsupported (the dialect-doesn't-
// have-this-feature case). The integration sweep asserts these surface
// as engine.ErrProbeNotApplicable rather than returning data.
var notApplicableOnES = map[string]bool{
	ISMState: true, // ISM is OpenSearch-only
}

// notApplicableOnOS is the OS counterpart.
var notApplicableOnOS = map[string]bool{
	ILMState:       true, // ILM is Elasticsearch-only
	DeprecationLog: true, // /_migration/deprecations is Elasticsearch-only
}

func TestIntegrationElasticsearch(t *testing.T) {
	skipIfNoDocker(t)
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), clusterStartTimeout+probeCallTimeout*time.Duration(len(known)))
	t.Cleanup(cancel)

	cc := startElasticsearch(t, ctx)
	sweepProbesAgainstCluster(t, ctx, cc, "elasticsearch", notApplicableOnES)
}

func TestIntegrationOpenSearch(t *testing.T) {
	skipIfNoDocker(t)
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), clusterStartTimeout+probeCallTimeout*time.Duration(len(known)))
	t.Cleanup(cancel)

	cc := startOpenSearch(t, ctx)
	sweepProbesAgainstCluster(t, ctx, cc, "opensearch", notApplicableOnOS)
}

// sweepProbesAgainstCluster runs every Known() probe against cc through
// probes.Connect + probes.New, asserting either a non-nil result (the
// happy path) or engine.ErrProbeNotApplicable (the cross-dialect skip
// path). Any other outcome — error, nil data — fails the subtest for
// that probe so an operator sees per-probe pass/fail in `go test -v`.
func sweepProbesAgainstCluster(t *testing.T, ctx context.Context, cc config.Context, dialect string, notApplicable map[string]bool) {
	t.Helper()

	cl, err := Connect(ctx, cc)
	if err != nil {
		t.Fatalf("Connect to %s: %v", dialect, err)
	}
	got := string(cl.Info.Dialect)
	if got != dialect {
		t.Fatalf("probed dialect = %q, expected %q (image mis-tagged?)", got, dialect)
	}
	t.Logf("connected to %s %s (cluster %q)", got, cl.Info.Version, cl.Info.ClusterName)

	reg := New(cl)
	for _, name := range Known() {
		t.Run(name, func(t *testing.T) {
			pctx, cancel := context.WithTimeout(ctx, probeCallTimeout)
			defer cancel()

			data, err := reg.Probe(pctx, name)
			if notApplicable[name] {
				if !errors.Is(err, engine.ErrProbeNotApplicable) {
					t.Errorf("expected ErrProbeNotApplicable on %s; got data=%v err=%v", dialect, data, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("probe %q: %v", name, err)
			}
			if data == nil {
				t.Errorf("probe %q returned nil data", name)
			}
		})
	}
}

func startElasticsearch(t *testing.T, ctx context.Context) config.Context {
	t.Helper()
	image := envOr("ESOPS_DOCTOR_TEST_ES_IMAGE", defaultESImage)

	c, err := tcgo.Run(ctx, image,
		tcgo.WithExposedPorts("9200/tcp"),
		tcgo.WithEnv(map[string]string{
			"discovery.type":         "single-node",
			"xpack.security.enabled": "false",
			// Constrain heap so a developer machine running both ES and
			// OS in parallel doesn't hit the OOM killer. Production
			// rules of thumb don't apply for a 1-shard test cluster.
			"ES_JAVA_OPTS": "-Xms512m -Xmx512m",
		}),
		tcgo.WithWaitStrategyAndDeadline(clusterStartTimeout,
			// /_cluster/health?wait_for_status=yellow blocks until the
			// node finishes recovering its single-node primaries; that's
			// the soonest the read endpoints respond reliably. Plain
			// GET / would race the master election on cold start.
			tcwait.ForHTTP("/_cluster/health?wait_for_status=yellow&timeout=60s").
				WithPort("9200/tcp").
				WithStartupTimeout(clusterStartTimeout)),
	)
	if err != nil {
		t.Fatalf("start elasticsearch: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	return contextFromContainer(t, ctx, c, "9200/tcp")
}

func startOpenSearch(t *testing.T, ctx context.Context) config.Context {
	t.Helper()
	image := envOr("ESOPS_DOCTOR_TEST_OS_IMAGE", defaultOSImage)

	c, err := tcgo.Run(ctx, image,
		tcgo.WithExposedPorts("9200/tcp"),
		tcgo.WithEnv(map[string]string{
			"discovery.type":              "single-node",
			"DISABLE_SECURITY_PLUGIN":     "true",
			"DISABLE_INSTALL_DEMO_CONFIG": "true",
			// Required by OS 2+ even when the security plugin is
			// disabled — the bootstrap script refuses to run without it.
			"OPENSEARCH_INITIAL_ADMIN_PASSWORD": "EsopsDoctorIntegrationTest_1!",
			"OPENSEARCH_JAVA_OPTS":              "-Xms512m -Xmx512m",
		}),
		tcgo.WithWaitStrategyAndDeadline(clusterStartTimeout,
			tcwait.ForHTTP("/_cluster/health?wait_for_status=yellow&timeout=60s").
				WithPort("9200/tcp").
				WithStartupTimeout(clusterStartTimeout)),
	)
	if err != nil {
		t.Fatalf("start opensearch: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	return contextFromContainer(t, ctx, c, "9200/tcp")
}

// contextFromContainer turns a started container into the config.Context
// that probes.Connect expects: an http URL keyed off the container's
// host + mapped port, with security knobs left at zero (the test
// containers run with security disabled).
func contextFromContainer(t *testing.T, ctx context.Context, c *tcgo.DockerContainer, port string) config.Context {
	t.Helper()
	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	mapped, err := c.MappedPort(ctx, "9200/tcp")
	if err != nil {
		t.Fatalf("mapped port: %v", err)
	}
	return config.Context{
		URL: "http://" + net.JoinHostPort(host, mapped.Port()),
	}
}

// skipIfNoDocker skips the test when the local Docker daemon is
// unreachable. Cheaper than letting testcontainers fail with a long
// stack trace; the message tells a developer running `go test -tags
// integration` what they need.
func skipIfNoDocker(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		return
	}
	if v := os.Getenv("DOCKER_HOST"); v != "" && !strings.HasPrefix(v, "unix://") {
		return
	}
	// Best-effort fallback: try the default Docker socket on macOS
	// (Colima / Rancher / Docker Desktop all expose one under $HOME).
	home, _ := os.UserHomeDir()
	for _, p := range []string{
		home + "/.colima/default/docker.sock",
		home + "/.rd/docker.sock",
		home + "/.docker/run/docker.sock",
	} {
		if _, err := os.Stat(p); err == nil {
			return
		}
	}
	t.Skip("no Docker socket found; skipping integration test")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
