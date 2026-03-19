package main

import (
	"edge-agent/core"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
	"net"
	"net/http"
	"os"
	"time"
)

type Agent struct {
	Loader *core.XdpLoader
	Policy core.Policy
	Model  *core.DlIdsModel
	Evidence sync.Map
	EvidenceTTL time.Duration
	evStop chan struct{}
	Token string
}

func ipToU32(ip string) (uint32, bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0, false
	}
	v4 := parsed.To4()
	if v4 == nil {
		return 0, false
	}
	return binary.LittleEndian.Uint32(v4), true
}

type evEntry struct {
	Count int
	Last  time.Time
}

func (a *Agent) startEvidenceEviction() {
	t := time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-a.evStop:
				t.Stop()
				return
			case <-t.C:
				now := time.Now()
				a.Evidence.Range(func(k, v interface{}) bool {
					e := v.(evEntry)
					if a.EvidenceTTL > 0 && now.Sub(e.Last) > a.EvidenceTTL {
						a.Evidence.Delete(k)
					}
					return true
				})
			}
		}
	}()
}

func (a *Agent) handleBlock(w http.ResponseWriter, r *http.Request) {
	if a.Token != "" {
		if r.Header.Get("Authorization") != "Bearer "+a.Token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	ip := r.URL.Query().Get("ip")
	ttlStr := r.URL.Query().Get("ttl")
	if ip == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ttl := time.Minute * 5
	if ttlStr != "" {
		if d, err := time.ParseDuration(ttlStr + "s"); err == nil {
			ttl = d
		}
	}
	if ok := a.Loader.AddIP(ip, ttl); !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	a.Loader.SaveSnapshot()
	w.WriteHeader(http.StatusOK)
}

func (a *Agent) handleUnblock(w http.ResponseWriter, r *http.Request) {
	if a.Token != "" {
		if r.Header.Get("Authorization") != "Bearer "+a.Token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if ok := a.Loader.RemoveIP(ip); !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	a.Loader.SaveSnapshot()
	w.WriteHeader(http.StatusOK)
}

func (a *Agent) handleStats(w http.ResponseWriter, r *http.Request) {
	if a.Token != "" {
		if r.Header.Get("Authorization") != "Bearer "+a.Token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	stats := a.Loader.Stats()
	enc := json.NewEncoder(w)
	enc.Encode(stats)
}

func (a *Agent) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if a.Token != "" {
		if r.Header.Get("Authorization") != "Bearer "+a.Token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	stats := a.Loader.Stats()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.Write([]byte("drops "))
	w.Write([]byte(fmt.Sprintf("%d\n", stats.Drops)))
	w.Write([]byte("passes "))
	w.Write([]byte(fmt.Sprintf("%d\n", stats.Passes)))
	w.Write([]byte("map_size "))
	w.Write([]byte(fmt.Sprintf("%d\n", stats.MapSize)))
}

func main() {
	nic := os.Getenv("NIC")
	if nic == "" {
		nic = "eth0"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	obj := os.Getenv("XDP_OBJ")
	if obj == "" {
		obj = "../../bpf/xdp_blocklist.o"
	}
	loader, err := core.NewXdpLoader(nic, obj)
	if err != nil {
		loader = &core.XdpLoader{}
	}
	if snap := os.Getenv("BLOCKLIST_SNAPSHOT"); snap != "" {
		loader.SetSnapshot(snap)
		loader.LoadSnapshot(snap)
	}
	model, _ := core.NewDlIdsModel(os.Getenv("MODEL_PATH"))
	ttl := 300 * time.Second
	if v := os.Getenv("EVIDENCE_TTL"); v != "" {
		if s, err := time.ParseDuration(v + "s"); err == nil && s > 0 {
			ttl = s
		}
	}
	a := &Agent{Loader: loader, Policy: core.DefaultPolicy(), Model: model, EvidenceTTL: ttl, evStop: make(chan struct{}, 1), Token: os.Getenv("TOKEN")}
	a.startEvidenceEviction()
	http.HandleFunc("/block", a.handleBlock)
	http.HandleFunc("/unblock", a.handleUnblock)
	http.HandleFunc("/stats", a.handleStats)
	http.HandleFunc("/metrics", a.handleMetrics)
	if cap := os.Getenv("PCAP"); cap != "" {
		go func() {
			tap := core.NewPacketTap()
			out := make(chan core.FlowSample, 1024)
			go func() {
				ft := core.NewFlowTable()
				for sample := range out {
					if a.Loader.IsBlocked(sample.Key.SrcIP) {
						a.Loader.RecordDrop()
						continue
					} else {
						a.Loader.RecordPass()
					}
					ft.UpdateEvent(sample.Key, sample.Ev)
					stateAny, ok := ft.M.Load(sample.Key)
					if !ok {
						continue
					}
					fs := stateAny.(core.FlowState)
					features := core.BuildFeatures(sample.Key, fs)
					pred, _ := a.Model.Predict(features)
					if ok, ttl := a.Policy.ShouldBlock(pred); ok {
						ce := evEntry{Count: 1, Last: time.Now()}
						if v, ok := a.Evidence.Load(sample.Key.SrcIP); ok {
							prev := v.(evEntry)
							ce.Count = prev.Count + 1
						}
						a.Evidence.Store(sample.Key.SrcIP, ce)
						if ce.Count >= a.Policy.MinEvidence {
							a.Loader.AddIP(sample.Key.SrcIP, ttl)
							a.Loader.SaveSnapshot()
							a.Evidence.Delete(sample.Key.SrcIP)
						}
					}
				}
			}()
			if len(cap) > 5 && cap[:5] == "live:" {
				iface := cap[5:]
				tap.StartLive(iface, out)
			} else if len(cap) > 6 && cap[:6] == "afxdp:" {
				iface := cap[6:]
				tap.StartAFXDP(iface, a.Loader, out)
			} else {
				tap.StartPcap(cap, out)
			}
		}()
	}
	http.ListenAndServe(":"+port, nil)
}
