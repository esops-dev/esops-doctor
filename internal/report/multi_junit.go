package report

import (
	"encoding/xml"
	"fmt"
	"io"
)

// MultiJUnit emits a single <testsuites> element containing one
// <testsuite> per cluster, mirroring how JUnit consumers (Jenkins,
// GitLab) render multi-suite test runs.
//
// A connect-failed cluster surfaces as a synthetic <testsuite> with a
// single <testcase name="connect"> in error state — preserving the CI
// view that "this cluster did not produce a clean run" without
// inventing a new XML shape.
func MultiJUnit(w io.Writer, clusters []ClusterReport, opts Options) error {
	suites := junitTestSuites{Name: junitClassName}
	for _, c := range clusters {
		if c.Errored() {
			suite := junitTestSuite{
				Name:     fleetSuiteName(c),
				Tests:    1,
				Errors:   1,
				Time:     formatJUnitSeconds(0),
				Hostname: c.Label,
				TestCases: []junitTestCase{{
					Name:      "connect",
					ClassName: junitClassName,
					Time:      formatJUnitSeconds(0),
					Error: &junitErrorTag{
						Type:    c.ConnectErrorClass,
						Message: c.ConnectError,
						Body:    c.ConnectError,
					},
				}},
			}
			suites.Suites = append(suites.Suites, suite)
			suites.Tests++
			suites.Errors++
			continue
		}
		built := buildJUnit(c.Header, c.Results, opts)
		suite := built.Suites[0]
		suite.Name = fleetSuiteName(c)
		suites.Suites = append(suites.Suites, suite)
		suites.Tests += suite.Tests
		suites.Failures += suite.Failures
		suites.Errors += suite.Errors
		suites.Skipped += suite.Skipped
	}
	suites.Time = formatJUnitSeconds(0)

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return fmt.Errorf("writing junit header: %w", err)
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(suites); err != nil {
		return fmt.Errorf("encoding multi-cluster junit report: %w", err)
	}
	if err := enc.Flush(); err != nil {
		return fmt.Errorf("flushing junit encoder: %w", err)
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		return fmt.Errorf("writing junit trailer: %w", err)
	}
	return nil
}

// fleetSuiteName picks the human-readable name for one cluster's
// <testsuite>. Falls back to the cluster name from the header when no
// explicit label was provided so the XML still attributes the run to
// a cluster.
func fleetSuiteName(c ClusterReport) string {
	if c.Label != "" {
		return c.Label
	}
	if c.Header.ClusterName != "" {
		return c.Header.ClusterName
	}
	return junitClassName
}
