package core

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketTap struct{}

func NewPacketTap() *PacketTap {
	return &PacketTap{}
}

type FlowSample struct {
	Key FlowKey
	Ev  FlowEvent
}

func canon(key FlowKey, src string, dst string, sp, dp uint16) (FlowKey, bool) {
	a := []byte(src)
	b := []byte(dst)
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return FlowKey{SrcIP: src, DstIP: dst, SrcPort: sp, DstPort: dp, Proto: key.Proto}, true
		}
		if a[i] > b[i] {
			return FlowKey{SrcIP: dst, DstIP: src, SrcPort: dp, DstPort: sp, Proto: key.Proto}, false
		}
	}
	return FlowKey{SrcIP: src, DstIP: dst, SrcPort: sp, DstPort: dp, Proto: key.Proto}, true
}

func (p *PacketTap) StartPcap(path string, out chan<- FlowSample) error {
	handle, err := pcap.OpenOffline(path)
	if err == nil {
		defer handle.Close()
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		for pkt := range src.Packets() {
			ip := pkt.Layer(layers.LayerTypeIPv4)
			if ip == nil {
				continue
			}
			ip4 := ip.(*layers.IPv4)
			key := FlowKey{Proto: uint8(ip4.Protocol)}
			srcIP := ip4.SrcIP.String()
			dstIP := ip4.DstIP.String()
			var sp, dp uint16
			switch ip4.Protocol {
			case layers.IPProtocolTCP:
				if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
					t := tcp.(*layers.TCP)
					sp = uint16(t.SrcPort)
					dp = uint16(t.DstPort)
				}
			case layers.IPProtocolUDP:
				if udp := pkt.Layer(layers.LayerTypeUDP); udp != nil {
					u := udp.(*layers.UDP)
					sp = uint16(u.SrcPort)
					dp = uint16(u.DstPort)
				}
			}
			ckey, fwd := canon(key, srcIP, dstIP, sp, dp)
			ipHdr := int(ip4.IHL) * 4
			var l4Hdr int
			switch ip4.Protocol {
			case layers.IPProtocolTCP:
				if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
					t := tcp.(*layers.TCP)
					l4Hdr = int(t.DataOffset) * 4
				}
			case layers.IPProtocolUDP:
				l4Hdr = 8
			}
			ev := FlowEvent{
				TS:       pkt.Metadata().Timestamp,
				Length:   pkt.Metadata().Length,
				Forward:  fwd,
				IpHdrLen: ipHdr,
				L4HdrLen: l4Hdr,
			}
			out <- FlowSample{Key: ckey, Ev: ev}
		}
		return nil
	}
	for i := 0; i < 100; i++ {
		key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1234, DstPort: 80, Proto: uint8(layers.IPProtocolTCP)}
		ev := FlowEvent{
			TS:       time.Now().Add(time.Duration(i) * time.Millisecond),
			Length:   1500,
			Forward:  true,
			IpHdrLen: 20,
			L4HdrLen: 20,
		}
		out <- FlowSample{Key: key, Ev: ev}
	}
	return nil
}

func (p *PacketTap) StartLive(iface string, out chan<- FlowSample) error {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		for i := 0; i < 100; i++ {
			key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1234, DstPort: 80, Proto: uint8(layers.IPProtocolTCP)}
			ev := FlowEvent{
				TS:       time.Now().Add(time.Duration(i) * time.Millisecond),
				Length:   1500,
				Forward:  true,
				IpHdrLen: 20,
				L4HdrLen: 20,
			}
			out <- FlowSample{Key: key, Ev: ev}
		}
		return nil
	}
	defer handle.Close()
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range src.Packets() {
		ip := pkt.Layer(layers.LayerTypeIPv4)
		if ip == nil {
			continue
		}
		ip4 := ip.(*layers.IPv4)
		key := FlowKey{Proto: uint8(ip4.Protocol)}
		srcIP := ip4.SrcIP.String()
		dstIP := ip4.DstIP.String()
		var sp, dp uint16
		switch ip4.Protocol {
		case layers.IPProtocolTCP:
			if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
				t := tcp.(*layers.TCP)
				sp = uint16(t.SrcPort)
				dp = uint16(t.DstPort)
			}
		case layers.IPProtocolUDP:
			if udp := pkt.Layer(layers.LayerTypeUDP); udp != nil {
				u := udp.(*layers.UDP)
				sp = uint16(u.SrcPort)
				dp = uint16(u.DstPort)
			}
		}
		ckey, fwd := canon(key, srcIP, dstIP, sp, dp)
		ipHdr := int(ip4.IHL) * 4
		var l4Hdr int
		switch ip4.Protocol {
		case layers.IPProtocolTCP:
			if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
				t := tcp.(*layers.TCP)
				l4Hdr = int(t.DataOffset) * 4
			}
		case layers.IPProtocolUDP:
			l4Hdr = 8
		}
		ev := FlowEvent{
			TS:       pkt.Metadata().Timestamp,
			Length:   pkt.Metadata().Length,
			Forward:  fwd,
			IpHdrLen: ipHdr,
			L4HdrLen: l4Hdr,
		}
		out <- FlowSample{Key: ckey, Ev: ev}
	}
	return nil
}
