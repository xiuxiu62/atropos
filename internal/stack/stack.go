package stack

import (
	"fmt"
	"log"

	"github.com/xiuxiu62/atropos/internal/icmp"
	"github.com/xiuxiu62/atropos/internal/ipv4"
	"github.com/xiuxiu62/atropos/internal/tun"
	"github.com/xiuxiu62/atropos/internal/udp"
)

type Stack struct {
	dev    tun.Device
	addr   [4]byte
	udpTbl udp.Table
}

func Create(device tun.Device, address [4]byte) Stack {
	s := Stack{dev: device, addr: address}
	s.udpTbl.Init(&s)
	return s
}

func (s *Stack) SendUDP(srcAddr, dstAddr [4]byte, srcPort, dstPort uint16, payload []byte) error {
	seg := udp.Serialize(srcAddr, dstAddr, srcPort, dstPort, payload)
	packet := ipv4.Serialize(srcAddr, dstAddr, ipv4.ProtoUDP, 64, seg)
	_, err := s.dev.Write(packet)
	return err
}

func (s *Stack) UDP() *udp.Table {
	return &s.udpTbl
}

func (s *Stack) Run() error {
	buf := make([]byte, 1500)
	for {
		n, err := s.dev.Read(buf)
		if err != nil {
			return fmt.Errorf("tun read: %w", err)
		}
		if err := s.handlePacket(buf[:n]); err != nil {
			log.Printf("stack: dropping packet %v", err)
		}
	}
}

func (s *Stack) handlePacket(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	if buf[0]>>4 != ipv4.Version {
		return nil
	}

	hdr, err := ipv4.Parse(buf)
	if err != nil {
		return fmt.Errorf("ipv4 parse: %w", err)
	}

	switch hdr.Protocol {
	case ipv4.ProtoICMP:
		return s.handleICMP(hdr)
	case ipv4.ProtoUDP:
		seg, err := udp.Parse(hdr.Payload)
		if err != nil {
			return fmt.Errorf("udp parse: %w", err)
		}
		s.udpTbl.Deliver(hdr.Src, hdr.Dst, seg)
		return nil
	case ipv4.ProtoTCP:
		log.Printf("tcp packet from %v, %d bytes (not yet handled)", hdr.Src, len(hdr.Payload))
		return nil
	default:
		return nil // unsupported protocol (IGMP, etc.) — not an error, just not implemented
	}
}

func (s *Stack) handleICMP(hdr ipv4.Header) error {
	msg, err := icmp.Parse(hdr.Payload)
	if err != nil {
		return fmt.Errorf("icmp parse: %w", err)
	}
	if msg.Type != icmp.TypeEchoRequest {
		return nil // ignore anything that isn't an echo request for now
	}

	reply := icmp.EchoReply(msg)
	packet := ipv4.Serialize(s.addr, hdr.Src, ipv4.ProtoICMP, 64, reply)

	_, err = s.dev.Write(packet)
	if err != nil {
		return fmt.Errorf("writing reply: %w", err)
	}
	return nil
}
