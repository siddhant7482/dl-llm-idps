package core

import (
	"sync"
	"time"
)

type FlowKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

type FlowEvent struct {
	TS       time.Time
	Length   int
	Forward  bool
	IpHdrLen int
	L4HdrLen int
}

type FlowState struct {
	FirstSeen    time.Time
	LastSeen     time.Time
	LastTS       time.Time
	LastFwdTS    time.Time
	LastBwdTS    time.Time
	TotalFwdPkts uint64
	TotalBwdPkts uint64
	FwdLenSum    float64
	FwdLenSqSum  float64
	BwdLenSum    float64
	BwdLenSqSum  float64
	FwdLenMax    int
	BwdLenMax    int
	AllLenSum    float64
	AllLenSqSum  float64
	AllLenMax    int
	FlowIatSum   float64
	FlowIatSqSum float64
	FlowIatMin   float64
	FlowIatMax   float64
	FlowIatCount uint64
	FwdIatSum    float64
	FwdIatSqSum  float64
	FwdIatMin    float64
	FwdIatMax    float64
	FwdIatCount  uint64
	BwdIatSum    float64
	BwdIatSqSum  float64
	BwdIatMin    float64
	BwdIatMax    float64
	BwdIatCount  uint64
	FwdHdrLenSum uint64
	BwdHdrLenSum uint64
	ActiveSum    float64
	ActiveSqSum  float64
	ActiveCount  uint64
	ActiveMin    float64
	ActiveMax    float64
	IdleSum      float64
	IdleSqSum    float64
	IdleCount    uint64
	IdleMin      float64
	IdleMax      float64
}

type FlowTable struct {
	M sync.Map
}

func NewFlowTable() *FlowTable {
	return &FlowTable{}
}

func (ft *FlowTable) UpdateEvent(key FlowKey, ev FlowEvent) {
	v, ok := ft.M.Load(key)
	if !ok {
		s := FlowState{FirstSeen: ev.TS, LastSeen: ev.TS}
		ft.M.Store(key, s)
		v, _ = ft.M.Load(key)
	}
	s := v.(FlowState)
	s.LastSeen = ev.TS
	if !s.LastTS.IsZero() && ev.TS.After(s.LastTS) {
		iat := ev.TS.Sub(s.LastTS).Seconds()
		s.FlowIatSum += iat
		s.FlowIatSqSum += iat * iat
		if s.FlowIatCount == 0 || iat < s.FlowIatMin {
			s.FlowIatMin = iat
		}
		if s.FlowIatCount == 0 || iat > s.FlowIatMax {
			s.FlowIatMax = iat
		}
		s.FlowIatCount++
		if iat > 1.0 {
			s.IdleSum += iat
			s.IdleSqSum += iat * iat
			if s.IdleCount == 0 || iat < s.IdleMin {
				s.IdleMin = iat
			}
			if s.IdleCount == 0 || iat > s.IdleMax {
				s.IdleMax = iat
			}
			s.IdleCount++
		} else {
			s.ActiveSum += iat
			s.ActiveSqSum += iat * iat
			if s.ActiveCount == 0 || iat < s.ActiveMin {
				s.ActiveMin = iat
			}
			if s.ActiveCount == 0 || iat > s.ActiveMax {
				s.ActiveMax = iat
			}
			s.ActiveCount++
		}
	}
	s.LastTS = ev.TS
	l := float64(ev.Length)
	if ev.Forward {
		s.TotalFwdPkts++
		s.FwdLenSum += l
		s.FwdLenSqSum += l * l
		if ev.Length > s.FwdLenMax {
			s.FwdLenMax = ev.Length
		}
		if !s.LastFwdTS.IsZero() && ev.TS.After(s.LastFwdTS) {
			iat := ev.TS.Sub(s.LastFwdTS).Seconds()
			s.FwdIatSum += iat
			s.FwdIatSqSum += iat * iat
			if s.FwdIatCount == 0 || iat < s.FwdIatMin {
				s.FwdIatMin = iat
			}
			if s.FwdIatCount == 0 || iat > s.FwdIatMax {
				s.FwdIatMax = iat
			}
			s.FwdIatCount++
		}
		s.LastFwdTS = ev.TS
		s.FwdHdrLenSum += uint64(ev.IpHdrLen + ev.L4HdrLen)
	} else {
		s.TotalBwdPkts++
		s.BwdLenSum += l
		s.BwdLenSqSum += l * l
		if ev.Length > s.BwdLenMax {
			s.BwdLenMax = ev.Length
		}
		if !s.LastBwdTS.IsZero() && ev.TS.After(s.LastBwdTS) {
			iat := ev.TS.Sub(s.LastBwdTS).Seconds()
			s.BwdIatSum += iat
			s.BwdIatSqSum += iat * iat
			if s.BwdIatCount == 0 || iat < s.BwdIatMin {
				s.BwdIatMin = iat
			}
			if s.BwdIatCount == 0 || iat > s.BwdIatMax {
				s.BwdIatMax = iat
			}
			s.BwdIatCount++
		}
		s.LastBwdTS = ev.TS
		s.BwdHdrLenSum += uint64(ev.IpHdrLen + ev.L4HdrLen)
	}
	s.AllLenSum += l
	s.AllLenSqSum += l * l
	if ev.Length > s.AllLenMax {
		s.AllLenMax = ev.Length
	}
	ft.M.Store(key, s)
}
