package core

import (
	"os"
	"testing"
)

func TestModelFallbackWhenRemoteUnavailable(t *testing.T) {
	os.Setenv("IDS_URL", "http://127.0.0.1:59999/invalid")
	m, _ := NewDlIdsModel("")
	p, _ := m.Predict(make([]float32, 52))
	if p.Class != "Benign" {
		t.Fatalf("expected Benign, got %s", p.Class)
	}
}
