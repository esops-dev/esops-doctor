package probes

import (
	"context"
	"fmt"
	"time"

	"github.com/esops-dev/esops-go/pkg/client"
)

// licenseShape is the rule-facing view of an Elasticsearch licence.
// Mirrors types.LicenseStatus with one derived field — DaysToExpiry —
// so a CEL condition can ask "is this licence within N days of
// expiring" without re-deriving the math from the absolute timestamp
// each time. Pointer-typed so a never-expires basic licence
// distinguishes from a 0-day-to-go expired licence at the leaf.
type licenseShape struct {
	Status       string   `json:"status"`
	Type         string   `json:"type"`
	IssuedTo     string   `json:"issued_to,omitempty"`
	Issuer       string   `json:"issuer,omitempty"`
	UID          string   `json:"uid,omitempty"`
	MaxNodes     int      `json:"max_nodes,omitempty"`
	IssuedAt     string   `json:"issued_at,omitempty"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
	DaysToExpiry *float64 `json:"days_to_expiry,omitempty"`
}

// fetchLicense calls LicenseInspector.License and pre-computes
// DaysToExpiry against probe-time so the matching rule's CEL stays
// simple. Negative days mean the licence has already expired —
// surfaced as-is so the rule consumer can render "expired N days ago"
// without a sentinel.
func fetchLicense(ctx context.Context, li client.LicenseInspector) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	got, err := li.License(ctx)
	if err != nil {
		return nil, fmt.Errorf("license probe: %w", err)
	}
	out := licenseShape{
		Status:   got.Status,
		Type:     got.Type,
		IssuedTo: got.IssuedTo,
		Issuer:   got.Issuer,
		UID:      got.UID,
		MaxNodes: got.MaxNodes,
	}
	if !got.IssuedAt.IsZero() {
		out.IssuedAt = got.IssuedAt.UTC().Format(time.RFC3339)
	}
	if got.ExpiresAt != nil {
		out.ExpiresAt = got.ExpiresAt.UTC().Format(time.RFC3339)
		days := time.Until(*got.ExpiresAt).Hours() / 24
		out.DaysToExpiry = &days
	}
	return jsonShape("license", out)
}
