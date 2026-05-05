package engine

import (
	"context"
	"errors"
	"testing"
)

func TestMapRegistryHit(t *testing.T) {
	r := MapRegistry{"nodes": []any{"a", "b"}}
	got, err := r.Probe(context.Background(), "nodes")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if list, ok := got.([]any); !ok || len(list) != 2 {
		t.Errorf("got %v, want 2-element slice", got)
	}
}

func TestMapRegistryMissReturnsSentinel(t *testing.T) {
	r := MapRegistry{}
	_, err := r.Probe(context.Background(), "nodes")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrProbeNotFound) {
		t.Errorf("err should match ErrProbeNotFound; got %v", err)
	}
}
