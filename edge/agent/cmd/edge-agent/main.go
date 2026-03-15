package main

import (
	"edge-agent/core"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"time"
)

type Agent struct {
	Loader *core.XdpLoader
	Policy core.Policy
	Model  *core.DlIdsModel
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

func (a *Agent) handleBlock(w http.ResponseWriter, r *http.Request) {
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
	w.WriteHeader(http.StatusOK)
}

func (a *Agent) handleUnblock(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if ok := a.Loader.RemoveIP(ip); !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (a *Agent) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := a.Loader.Stats()
	enc := json.NewEncoder(w)
	enc.Encode(stats)
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
	model, _ := core.NewDlIdsModel(os.Getenv("MODEL_PATH"))
	a := &Agent{Loader: loader, Policy: core.DefaultPolicy(), Model: model}
	http.HandleFunc("/block", a.handleBlock)
	http.HandleFunc("/unblock", a.handleUnblock)
	http.HandleFunc("/stats", a.handleStats)
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
						a.Loader.AddIP(sample.Key.SrcIP, ttl)
					}
				}
			}()
			if len(cap) > 5 && cap[:5] == "live:" {
				iface := cap[5:]
				tap.StartLive(iface, out)
			} else {
				tap.StartPcap(cap, out)
			}
		}()
	}
	http.ListenAndServe(":"+port, nil)
}
