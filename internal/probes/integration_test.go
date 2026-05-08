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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/esops-dev/esops-go/pkg/config"

	tcgo "github.com/testcontainers/testcontainers-go"
	tcwait "github.com/testcontainers/testcontainers-go/wait"

	"github.com/esops-dev/esops-doctor/internal/engine"
)

// Pinned images for the fast-path integration matrix. Override via env
// (ESOPS_DOCTOR_TEST_ES_IMAGE / ESOPS_DOCTOR_TEST_OS_IMAGE) to extend
// the matrix in nightly runs without touching the test source.
const (
	defaultESImage = "docker.elastic.co/elasticsearch/elasticsearch:9.0.0"
	defaultOSImage = "opensearchproject/opensearch:2.18.0"

	clusterStartTimeout = 3 * time.Minute
	probeCallTimeout    = 30 * time.Second
)

// notApplicableOnES is the set of probes whose upstream adapter for
// Elasticsearch returns client.ErrUnsupported in this test setup. That
// covers two cases collapsed into the same sentinel: a feature the
// dialect genuinely lacks (none today), and a feature the test cluster
// has switched off (api_keys / service_tokens, both unavailable when
// xpack.security.enabled=false — the test container's posture). The
// integration sweep asserts these surface as engine.ErrProbeNotApplicable
// rather than returning data.
var notApplicableOnES = map[string]bool{
	ISMState:      true, // ISM is OpenSearch-only
	APIKeys:       true, // Security disabled in the test container; upstream returns ErrUnsupported
	ServiceTokens: true, // Same as api_keys — security off ⇒ unsupported
	// FollowerStats / AutoFollowPatterns are CCR-licence-gated upstream
	// (404 → ErrUnsupported), but the OSS-style ES test container
	// answers /_ccr/* with an empty body and a 200, so the probes
	// succeed with empty data rather than skipping. The doctor rules
	// behind these probes treat the empty list as a vacuous pass —
	// indistinguishable from "no CCR configured here" — so the
	// integration sweep does not need a special case.
	License: true, // /_license is unregistered on the licensing-stripped test build (404 → ErrUnsupported)
}

// notApplicableOnOS is the OS counterpart.
var notApplicableOnOS = map[string]bool{
	ILMState:           true, // ILM is Elasticsearch-only
	DeprecationLog:     true, // /_migration/deprecations is Elasticsearch-only
	APIKeys:            true, // API keys are an Elasticsearch-only surface
	ServiceTokens:      true, // Service tokens are an Elasticsearch-only surface
	FollowerStats:      true, // CCR is Elasticsearch-only — OS exposes a divergent /_plugins/_replication surface
	AutoFollowPatterns: true, // CCR auto-follow is Elasticsearch-only on the same terms as FollowerStats
	License:            true, // /_license is an Elasticsearch-only surface; OS has no commercial-licence model
}

// skippedOnOS lists probes the OS sweep does not exercise. The OS test
// container runs with DISABLE_SECURITY_PLUGIN=true to avoid TLS / admin
// credential plumbing, which means /_plugins/_security/api/* doesn't
// answer. Per the upstream SecurityAuditor / AuditLogInspector / Realms
// contracts those probes should surface a disabled-sentinel, but the
// adapters currently raise HTTP 400 from the missing handler. Drop
// entries here when the plugin is enabled in the test container, or
// when upstream returns the documented disabled-sentinel.
var skippedOnOS = map[string]bool{
	SecurityAudit: true,
	AuditLog:      true,
	Realms:        true,
}

func TestIntegrationElasticsearch(t *testing.T) {
	skipIfNoDocker(t)
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), clusterStartTimeout+probeCallTimeout*time.Duration(len(known)))
	t.Cleanup(cancel)

	cc := startElasticsearch(t, ctx)
	sweepProbesAgainstCluster(t, ctx, cc, "elasticsearch", notApplicableOnES, skippedOnESForVersion(t, ctx, cc))
}

// skippedOnESForVersion returns the per-image skip set for the connected
// Elasticsearch version. Today the only entry is security_audit on ES <
// 9.x: the test container starts with xpack.security.enabled=false, and
// on those older versions GET /_security/user answers HTTP 405
// "Incorrect HTTP method ... allowed: [POST]" rather than the
// disabled-security bodies the upstream adapter recognises in
// isSecurityDisabledBody. The audit therefore returns an error rather
// than Status.Enabled=false.
//
// Drop the entry once esops-go's ES adapter learns to treat the 405
// "method not allowed" body as a disabled-security signal, or once the
// integration container is reconfigured with security enabled (which
// would require admin credentials + TLS plumbing that the test setup
// deliberately avoids).
func skippedOnESForVersion(t *testing.T, ctx context.Context, cc config.Context) map[string]bool {
	t.Helper()
	cl, err := Connect(ctx, cc)
	if err != nil {
		// Connect already runs once inside sweepProbesAgainstCluster; if
		// it fails here, return nil and let the sweep surface the real
		// failure with its richer message.
		return nil
	}
	major := majorVersion(cl.Info.Version)
	if major > 0 && major < 9 {
		return map[string]bool{SecurityAudit: true}
	}
	return nil
}

// majorVersion parses the leading integer of a "X.Y.Z" version string.
// Returns 0 when the string is empty or doesn't lead with a digit, so
// callers can treat 0 as "unknown — don't skip anything".
func majorVersion(v string) int {
	dot := strings.IndexByte(v, '.')
	if dot <= 0 {
		return 0
	}
	n, err := strconv.Atoi(v[:dot])
	if err != nil {
		return 0
	}
	return n
}

func TestIntegrationOpenSearch(t *testing.T) {
	skipIfNoDocker(t)
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), clusterStartTimeout+probeCallTimeout*time.Duration(len(known)))
	t.Cleanup(cancel)

	cc := startOpenSearch(t, ctx)
	sweepProbesAgainstCluster(t, ctx, cc, "opensearch", notApplicableOnOS, skippedOnOS)
}

// sweepProbesAgainstCluster runs every Known() probe against cc through
// probes.Connect + probes.New, asserting either a non-nil result (the
// happy path) or engine.ErrProbeNotApplicable (the cross-dialect skip
// path). Any other outcome — error, nil data — fails the subtest for
// that probe so an operator sees per-probe pass/fail in `go test -v`.
//
// skip lists probe names whose subtest should be skipped entirely (e.g.
// because the test container deliberately disables the feature the
// probe queries). Pass nil to exercise every probe.
func sweepProbesAgainstCluster(t *testing.T, ctx context.Context, cc config.Context, dialect string, notApplicable, skip map[string]bool) {
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
			if skip[name] {
				t.Skipf("probe %q skipped on %s by test setup", name, dialect)
			}
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
