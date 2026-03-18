package core

import (
	"testing"
	"time"
)

func TestBuildFeaturesShapeAndBasicValues(t *testing.T) {
	k := FlowKey{SrcIP: "1.2.3.4", DstIP: "5.6.7.8", SrcPort: 1234, DstPort: 80, Proto: 6}
	s := FlowState{FirstSeen: time.Now().Add(-2 * time.Second), LastSeen: time.Now().Add(-1 * time.Second)}
	ev1 := FlowEvent{TS: time.Now().Add(-900 * time.Millisecond), Length: 100, PayloadLen: 50, Forward: true, IpHdrLen: 20, L4HdrLen: 20, TcpWindow: 512}
	ev2 := FlowEvent{TS: time.Now().Add(-800 * time.Millisecond), Length: 200, PayloadLen: 0, Forward: false, IpHdrLen: 20, L4HdrLen: 20, TcpWindow: 256}
	ft := NewFlowTable()
	ft.M.Store(k, s)
	ft.UpdateEvent(k, ev1)
	ft.UpdateEvent(k, ev2)
	v, ok := ft.M.Load(k)
	if !ok {
		t.Fatalf("missing flow")
	}
	fs := v.(FlowState)
	f := BuildFeatures(k, fs)
	if len(f) != 52 {
		t.Fatalf("len=%d", len(f))
	}
	if f[1] < 1 || f[2] < 1 {
		t.Fatalf("pkt counts invalid")
	}
	if f[41] == 0 {
		t.Fatalf("init window missing")
	}
}
