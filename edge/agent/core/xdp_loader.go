package core

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type XdpLoader struct {
	nic         string
	obj         string
	prog        link.Link
	mBlocked    *ebpf.Map
	mCounters   *ebpf.Map
	expirations sync.Map
	memBlocked  sync.Map
	memDrops    uint64
	memPasses   uint64
}

type Stats struct {
	Drops   uint64 `json:"drops"`
	Passes  uint64 `json:"passes"`
	MapSize uint64 `json:"map_size"`
}

func NewXdpLoader(nic, obj string) (*XdpLoader, error) {
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		return &XdpLoader{}, err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return &XdpLoader{}, err
	}
	prog := coll.Programs["xdp_blocklist_prog"]
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifaceIndex(nic),
		Flags:     0,
	})
	if err != nil {
		return &XdpLoader{}, err
	}
	mBlocked := coll.Maps["blocked_ips"]
	mCounters := coll.Maps["counters"]
	loader := &XdpLoader{nic: nic, obj: obj, prog: l, mBlocked: mBlocked, mCounters: mCounters}
	return loader, nil
}

func ifaceIndex(name string) int {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0
	}
	return iface.Index
}

func ipToKey(ip string) (uint32, bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0, false
	}
	v4 := parsed.To4()
	if v4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(v4), true
}

func (l *XdpLoader) AddIP(ip string, ttl time.Duration) bool {
	key, ok := ipToKey(ip)
	if !ok {
		return false
	}
	val := uint8(1)
	if l.mBlocked != nil {
		if err := l.mBlocked.Update(&key, &val, ebpf.UpdateAny); err != nil {
			return false
		}
	} else {
		l.memBlocked.Store(key, val)
	}
	if ttl > 0 {
		l.expirations.Store(key, time.Now().Add(ttl))
		go l.expireLoop(key, ttl)
	}
	return true
}

func (l *XdpLoader) IsBlocked(ip string) bool {
	key, ok := ipToKey(ip)
	if !ok {
		return false
	}
	if l.mBlocked != nil {
		var v uint8
		if err := l.mBlocked.Lookup(&key, &v); err == nil {
			return true
		}
		return false
	}
	_, ok2 := l.memBlocked.Load(key)
	return ok2
}

func (l *XdpLoader) RecordDrop() {
	if l.mCounters == nil {
		atomic.AddUint64(&l.memDrops, 1)
	}
}

func (l *XdpLoader) RecordPass() {
	if l.mCounters == nil {
		atomic.AddUint64(&l.memPasses, 1)
	}
}

func (l *XdpLoader) expireLoop(key uint32, ttl time.Duration) {
	time.Sleep(ttl)
	if v, ok := l.expirations.Load(key); ok {
		if time.Now().After(v.(time.Time)) {
			if l.mBlocked != nil {
				l.mBlocked.Delete(&key)
			} else {
				l.memBlocked.Delete(key)
			}
			l.expirations.Delete(key)
		}
	}
}

func (l *XdpLoader) RemoveIP(ip string) bool {
	key, ok := ipToKey(ip)
	if !ok {
		return false
	}
	if l.mBlocked != nil {
		if err := l.mBlocked.Delete(&key); err != nil {
			return false
		}
	} else {
		l.memBlocked.Delete(key)
	}
	l.expirations.Delete(key)
	return true
}

func (l *XdpLoader) Stats() Stats {
	var drops, passes uint64
	var idx uint32
	if l.mCounters != nil {
		idx = 0
		l.mCounters.Lookup(&idx, &drops)
		idx = 1
		l.mCounters.Lookup(&idx, &passes)
	} else {
		drops = atomic.LoadUint64(&l.memDrops)
		passes = atomic.LoadUint64(&l.memPasses)
	}
	var size uint64
	if l.mBlocked != nil {
		it := l.mBlocked.Iterate()
		var k uint32
		var v uint8
		for it.Next(&k, &v) {
			size++
		}
	} else {
		l.memBlocked.Range(func(_, _ interface{}) bool {
			size++
			return true
		})
	}
	return Stats{Drops: drops, Passes: passes, MapSize: size}
}
