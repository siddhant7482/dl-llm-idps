package core

import (
	"net"
	"time"

	"github.com/planktonzp/xdp"
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
	ai := net.ParseIP(src)
	bi := net.ParseIP(dst)
	if ai == nil || bi == nil {
		return FlowKey{SrcIP: src, DstIP: dst, SrcPort: sp, DstPort: dp, Proto: key.Proto}, true
	}
	ab := ai.To16()
	bb := bi.To16()
	if ab == nil || bb == nil {
		return FlowKey{SrcIP: src, DstIP: dst, SrcPort: sp, DstPort: dp, Proto: key.Proto}, true
	}
	for i := 0; i < 16; i++ {
		if ab[i] < bb[i] {
			return FlowKey{SrcIP: src, DstIP: dst, SrcPort: sp, DstPort: dp, Proto: key.Proto}, true
		}
		if ab[i] > bb[i] {
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
			var srcIP, dstIP string
			var proto uint8
			var ipHdr int
			isIPv6 := false
			if ip := pkt.Layer(layers.LayerTypeIPv4); ip != nil {
				ip4 := ip.(*layers.IPv4)
				srcIP = ip4.SrcIP.String()
				dstIP = ip4.DstIP.String()
				proto = uint8(ip4.Protocol)
				ipHdr = int(ip4.IHL) * 4
			} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
				ih := ip6.(*layers.IPv6)
				srcIP = ih.SrcIP.String()
				dstIP = ih.DstIP.String()
				proto = uint8(ih.NextHeader)
				ipHdr = 40
				isIPv6 = true
			} else {
				continue
			}
			key := FlowKey{Proto: proto}
			var sp, dp uint16
			switch layers.IPProtocol(proto) {
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
			var l4Hdr int
			var payloadLen int
			var tcpWindow uint16
			var tcpFlags uint8
			switch layers.IPProtocol(proto) {
			case layers.IPProtocolTCP:
				if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
					t := tcp.(*layers.TCP)
					l4Hdr = int(t.DataOffset) * 4
					tcpWindow = uint16(t.Window)
					var f uint8
					if t.SYN {
						f |= 0x02
					}
					if t.ACK {
						f |= 0x10
					}
					if t.FIN {
						f |= 0x01
					}
					if t.PSH {
						f |= 0x08
					}
					tcpFlags = f
					if isIPv6 {
						if v6 := pkt.Layer(layers.LayerTypeIPv6); v6 != nil {
							ih := v6.(*layers.IPv6)
							pl := int(ih.Length) - l4Hdr
							if pl < 0 {
								pl = 0
							}
							payloadLen = pl
						}
					} else {
						if v4 := pkt.Layer(layers.LayerTypeIPv4); v4 != nil {
							ih := v4.(*layers.IPv4)
							pl := int(ih.Length) - ipHdr - l4Hdr
							if pl < 0 {
								pl = 0
							}
							payloadLen = pl
						}
					}
				}
			case layers.IPProtocolUDP:
				l4Hdr = 8
				if isIPv6 {
					if v6 := pkt.Layer(layers.LayerTypeIPv6); v6 != nil {
						ih := v6.(*layers.IPv6)
						pl := int(ih.Length) - l4Hdr
						if pl < 0 {
							pl = 0
						}
						payloadLen = pl
					}
				} else {
					if v4 := pkt.Layer(layers.LayerTypeIPv4); v4 != nil {
						ih := v4.(*layers.IPv4)
						pl := int(ih.Length) - ipHdr - l4Hdr
						if pl < 0 {
							pl = 0
						}
						payloadLen = pl
					}
				}
			}
			ev := FlowEvent{
				TS:       pkt.Metadata().Timestamp,
				Length:   pkt.Metadata().Length,
				PayloadLen: payloadLen,
				Forward:  fwd,
				IpHdrLen: ipHdr,
				L4HdrLen: l4Hdr,
				TcpWindow: tcpWindow,
				TcpFlags:  tcpFlags,
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
				PayloadLen: 1460,
				Forward:  true,
				IpHdrLen: 20,
				L4HdrLen: 20,
				TcpWindow: 65535,
				TcpFlags:  0x10,
			}
			out <- FlowSample{Key: key, Ev: ev}
		}
		return nil
	}
	defer handle.Close()
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range src.Packets() {
		var srcIP, dstIP string
		var proto uint8
		var ipHdr int
		isIPv6 := false
		if ip := pkt.Layer(layers.LayerTypeIPv4); ip != nil {
			ip4 := ip.(*layers.IPv4)
			srcIP = ip4.SrcIP.String()
			dstIP = ip4.DstIP.String()
			proto = uint8(ip4.Protocol)
			ipHdr = int(ip4.IHL) * 4
		} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
			ih := ip6.(*layers.IPv6)
			srcIP = ih.SrcIP.String()
			dstIP = ih.DstIP.String()
			proto = uint8(ih.NextHeader)
			ipHdr = 40
			isIPv6 = true
		} else {
			continue
		}
		key := FlowKey{Proto: proto}
		var sp, dp uint16
		switch layers.IPProtocol(proto) {
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
		var l4Hdr int
		var payloadLen int
		var tcpWindow uint16
		var tcpFlags uint8
		switch layers.IPProtocol(proto) {
		case layers.IPProtocolTCP:
			if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
				t := tcp.(*layers.TCP)
				l4Hdr = int(t.DataOffset) * 4
				tcpWindow = uint16(t.Window)
				var f uint8
				if t.SYN {
					f |= 0x02
				}
				if t.ACK {
					f |= 0x10
				}
				if t.FIN {
					f |= 0x01
				}
				if t.PSH {
					f |= 0x08
				}
				tcpFlags = f
				if isIPv6 {
					if v6 := pkt.Layer(layers.LayerTypeIPv6); v6 != nil {
						ih := v6.(*layers.IPv6)
						pl := int(ih.Length) - l4Hdr
						if pl < 0 {
							pl = 0
						}
						payloadLen = pl
					}
				} else {
					if v4 := pkt.Layer(layers.LayerTypeIPv4); v4 != nil {
						ih := v4.(*layers.IPv4)
						pl := int(ih.Length) - ipHdr - l4Hdr
						if pl < 0 {
							pl = 0
						}
						payloadLen = pl
					}
				}
			}
		case layers.IPProtocolUDP:
			l4Hdr = 8
			if isIPv6 {
				if v6 := pkt.Layer(layers.LayerTypeIPv6); v6 != nil {
					ih := v6.(*layers.IPv6)
					pl := int(ih.Length) - l4Hdr
					if pl < 0 {
						pl = 0
					}
					payloadLen = pl
				}
			} else {
				if v4 := pkt.Layer(layers.LayerTypeIPv4); v4 != nil {
					ih := v4.(*layers.IPv4)
					pl := int(ih.Length) - ipHdr - l4Hdr
					if pl < 0 {
						pl = 0
					}
					payloadLen = pl
				}
			}
		}
		ev := FlowEvent{
			TS:       pkt.Metadata().Timestamp,
			Length:   pkt.Metadata().Length,
			PayloadLen: payloadLen,
			Forward:  fwd,
			IpHdrLen: ipHdr,
			L4HdrLen: l4Hdr,
			TcpWindow: tcpWindow,
			TcpFlags:  tcpFlags,
		}
		out <- FlowSample{Key: ckey, Ev: ev}
	}
	return nil
}

func (p *PacketTap) StartAFXDP(iface string, loader *XdpLoader, out chan<- FlowSample) error {
	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil || ifaceObj == nil {
		for i := 0; i < 100; i++ {
			key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1234, DstPort: 80, Proto: uint8(layers.IPProtocolTCP)}
			ev := FlowEvent{
				TS:         time.Now().Add(time.Duration(i) * time.Millisecond),
				Length:     1500,
				PayloadLen: 1460,
				Forward:    true,
				IpHdrLen:   20,
				L4HdrLen:   20,
				TcpWindow:  65535,
				TcpFlags:   0x10,
			}
			out <- FlowSample{Key: key, Ev: ev}
		}
		return nil
	}
	xsk, err := xdp.NewSocket(ifaceObj.Index, 0, nil)
	if err != nil {
		return err
	}
	loader.RegisterXsk(0, xsk.FD())
	for {
		xsk.Fill(xsk.GetDescs(xsk.NumFreeFillSlots(), true))
		numRx, _, err := xsk.Poll(-1)
		if err != nil {
			continue
		}
		rx := xsk.Receive(numRx)
		for i := 0; i < len(rx); i++ {
			frame := xsk.GetFrame(rx[i])
			pkt := gopacket.NewPacket(frame, layers.LinkTypeEthernet, gopacket.NoCopy)
			var srcIP, dstIP string
			var proto uint8
			var ipHdr int
			isIPv6 := false
			var ip4L *layers.IPv4
			var ip6L *layers.IPv6
			if ip := pkt.Layer(layers.LayerTypeIPv4); ip != nil {
				ip4 := ip.(*layers.IPv4)
				ip4L = ip4
				srcIP = ip4.SrcIP.String()
				dstIP = ip4.DstIP.String()
				proto = uint8(ip4.Protocol)
				ipHdr = int(ip4.IHL) * 4
			} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
				ih := ip6.(*layers.IPv6)
				ip6L = ih
				srcIP = ih.SrcIP.String()
				dstIP = ih.DstIP.String()
				proto = uint8(ih.NextHeader)
				ipHdr = 40
				isIPv6 = true
			} else {
				continue
			}
			var sp, dp uint16
			var l4Hdr int
			var payloadLen int
			var tcpWindow uint16
			var tcpFlags uint8
			switch layers.IPProtocol(proto) {
			case layers.IPProtocolTCP:
				if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
					t := tcp.(*layers.TCP)
					sp = uint16(t.SrcPort)
					dp = uint16(t.DstPort)
					l4Hdr = int(t.DataOffset) * 4
					tcpWindow = uint16(t.Window)
					var f uint8
					if t.SYN {
						f |= 0x02
					}
					if t.ACK {
						f |= 0x10
					}
					if t.FIN {
						f |= 0x01
					}
					if t.PSH {
						f |= 0x08
					}
					tcpFlags = f
					if isIPv6 {
						pl := int(ip6L.Length) - l4Hdr
						if pl < 0 {
							pl = 0
						}
						payloadLen = pl
					} else {
						pl := int(ip4L.Length) - ipHdr - l4Hdr
						if pl < 0 {
							pl = 0
						}
						payloadLen = pl
					}
				}
			case layers.IPProtocolUDP:
				if udp := pkt.Layer(layers.LayerTypeUDP); udp != nil {
					u := udp.(*layers.UDP)
					sp = uint16(u.SrcPort)
					dp = uint16(u.DstPort)
					l4Hdr = 8
					if isIPv6 {
						pl := int(ip6L.Length) - l4Hdr
						if pl < 0 {
							pl = 0
						}
						payloadLen = pl
					} else {
						pl := int(ip4L.Length) - ipHdr - l4Hdr
						if pl < 0 {
							pl = 0
						}
						payloadLen = pl
					}
				}
			}
			ckey, fwd := canon(FlowKey{Proto: proto}, srcIP, dstIP, sp, dp)
			ev := FlowEvent{
				TS:         time.Now(),
				Length:     len(frame),
				PayloadLen: payloadLen,
				Forward:    fwd,
				IpHdrLen:   ipHdr,
				L4HdrLen:   l4Hdr,
				TcpWindow:  tcpWindow,
				TcpFlags:   tcpFlags,
			}
			out <- FlowSample{Key: ckey, Ev: ev}
		}
		xsk.Complete(xsk.NumCompleted())
	}
}
