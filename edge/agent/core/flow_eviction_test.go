package core

import (
	"os"
	"testing"
	"time"
)

func TestFlowEvictionPurgesExpired(t *testing.T) {
	os.Setenv("FLOW_TTL", "1")
	ft := NewFlowTable()
	k := FlowKey{SrcIP: "9.9.9.9", DstIP: "8.8.8.8", SrcPort: 1, DstPort: 2, Proto: 17}
	s := FlowState{FirstSeen: time.Now().Add(-3 * time.Second), LastSeen: time.Now().Add(-3 * time.Second)}
	ft.M.Store(k, s)
	ft.PurgeExpired()
	_, ok := ft.M.Load(k)
	if ok {
		t.Fatalf("not purged")
	}
	ft.Close()
}
