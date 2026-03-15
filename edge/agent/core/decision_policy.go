package core

import "time"

type Policy struct {
	Thresholds  map[string]float32
	TTL         map[string]time.Duration
	MinEvidence int
}

func DefaultPolicy() Policy {
	return Policy{
		Thresholds: map[string]float32{
			"DDoS attacks-LOIC-HTTP": 0.98,
			"DDOS attack-HOIC":       0.98,
			"SSH-Bruteforce":         0.995,
			"Bot":                    0.97,
		},
		TTL: map[string]time.Duration{
			"DDoS attacks-LOIC-HTTP": 300 * time.Second,
			"DDOS attack-HOIC":       300 * time.Second,
			"SSH-Bruteforce":         600 * time.Second,
			"Bot":                    1200 * time.Second,
		},
		MinEvidence: 2,
	}
}

func (p Policy) ShouldBlock(pred Prediction) (bool, time.Duration) {
	th, ok := p.Thresholds[pred.Class]
	if !ok {
		return false, 0
	}
	if pred.Confidence < th {
		return false, 0
	}
	return true, p.TTL[pred.Class]
}
