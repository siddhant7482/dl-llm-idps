package core

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
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
	mBlockedV6  *ebpf.Map
	mCounters   *ebpf.Map
	mXsks       *ebpf.Map
	mQidConf    *ebpf.Map
	expirations sync.Map
	expirationsV6 sync.Map
	memBlocked  sync.Map
	memBlockedV6 sync.Map
	memDrops    uint64
	memPasses   uint64
	snapshotPath string
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
	mBlockedV6 := coll.Maps["blocked_ipv6"]
	mCounters := coll.Maps["counters"]
	mXsks := coll.Maps["xsks_map"]
	mQidConf := coll.Maps["qidconf_map"]
	loader := &XdpLoader{
		nic: nic, obj: obj, prog: l,
		mBlocked: mBlocked, mBlockedV6: mBlockedV6, mCounters: mCounters,
		mXsks: mXsks, mQidConf: mQidConf,
	}
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

func ipToKeyV6(ip string) ([16]byte, bool) {
	var out [16]byte
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return out, false
	}
	v6 := parsed.To16()
	if v6 == nil || parsed.To4() != nil {
		return out, false
	}
	copy(out[:], v6[:16])
	return out, true
}

func (l *XdpLoader) AddIP(ip string, ttl time.Duration) bool {
	key, ok := ipToKey(ip)
	val := uint8(1)
	if ok {
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
	key6, ok6 := ipToKeyV6(ip)
	if !ok6 {
		return false
	}
	if l.mBlockedV6 != nil {
		if err := l.mBlockedV6.Update(&key6, &val, ebpf.UpdateAny); err != nil {
			return false
		}
	} else {
		l.memBlockedV6.Store(key6, val)
	}
	if ttl > 0 {
		l.expirationsV6.Store(key6, time.Now().Add(ttl))
		go l.expireLoopV6(key6, ttl)
	}
	return true
}

func (l *XdpLoader) IsBlocked(ip string) bool {
	key, ok := ipToKey(ip)
	if !ok {
		key6, ok6 := ipToKeyV6(ip)
		if !ok6 {
			return false
		}
		if l.mBlockedV6 != nil {
			var v uint8
			if err := l.mBlockedV6.Lookup(&key6, &v); err == nil {
				return true
			}
			return false
		}
		_, okm := l.memBlockedV6.Load(key6)
		return okm
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

func (l *XdpLoader) expireLoopV6(key [16]byte, ttl time.Duration) {
	time.Sleep(ttl)
	if v, ok := l.expirationsV6.Load(key); ok {
		if time.Now().After(v.(time.Time)) {
			if l.mBlockedV6 != nil {
				l.mBlockedV6.Delete(&key)
			} else {
				l.memBlockedV6.Delete(key)
			}
			l.expirationsV6.Delete(key)
		}
	}
}

func (l *XdpLoader) RemoveIP(ip string) bool {
	key, ok := ipToKey(ip)
	if !ok {
		key6, ok6 := ipToKeyV6(ip)
		if !ok6 {
			return false
		}
		if l.mBlockedV6 != nil {
			if err := l.mBlockedV6.Delete(&key6); err != nil {
				return false
			}
		} else {
			l.memBlockedV6.Delete(key6)
		}
		l.expirationsV6.Delete(key6)
		return true
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
	if l.mBlockedV6 != nil {
		it6 := l.mBlockedV6.Iterate()
		var k6 [16]byte
		var v6 uint8
		for it6.Next(&k6, &v6) {
			size++
		}
	} else {
		l.memBlockedV6.Range(func(_, _ interface{}) bool {
			size++
			return true
		})
	}
	return Stats{Drops: drops, Passes: passes, MapSize: size}
}

func (l *XdpLoader) RegisterXsk(queueID int, fd int) bool {
	if l.mXsks == nil || l.mQidConf == nil {
		return false
	}
	key := uint32(queueID)
	val := uint32(fd)
	if err := l.mXsks.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return false
	}
	one := uint32(1)
	if err := l.mQidConf.Update(&key, &one, ebpf.UpdateAny); err != nil {
		return false
	}
	return true
}

func (l *XdpLoader) UnregisterXsk(queueID int) bool {
	if l.mXsks == nil || l.mQidConf == nil {
		return false
	}
	key := uint32(queueID)
	l.mXsks.Delete(&key)
	l.mQidConf.Delete(&key)
	return true
}

type snapshotEntry struct {
	IP      string `json:"ip"`
	Version int    `json:"version"`
	Expiry  int64  `json:"expiry"`
}

func (l *XdpLoader) SetSnapshot(path string) {
	l.snapshotPath = path
}

func (l *XdpLoader) SaveSnapshot() error {
	if l.snapshotPath == "" {
		return nil
	}
	var list []snapshotEntry
	l.expirations.Range(func(k, v interface{}) bool {
		key := k.(uint32)
		exp := v.(time.Time)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], key)
		ip := net.IPv4(b[0], b[1], b[2], b[3]).String()
		list = append(list, snapshotEntry{IP: ip, Version: 4, Expiry: exp.Unix()})
		return true
	})
	l.expirationsV6.Range(func(k, v interface{}) bool {
		key := k.([16]byte)
		exp := v.(time.Time)
		ip := net.IP(key[:]).String()
		list = append(list, snapshotEntry{IP: ip, Version: 6, Expiry: exp.Unix()})
		return true
	})
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return os.WriteFile(l.snapshotPath, b, 0644)
}

func (l *XdpLoader) LoadSnapshot(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var list []snapshotEntry
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	now := time.Now()
	for _, e := range list {
		exp := time.Unix(e.Expiry, 0)
		if exp.After(now) {
			ttl := time.Until(exp)
			l.AddIP(e.IP, ttl)
		}
	}
	return nil
}
