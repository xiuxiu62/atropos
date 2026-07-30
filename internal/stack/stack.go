package stack

import (
	"fmt"
	"log"

	"github.com/xiuxiu62/atropos/internal/icmp"
	"github.com/xiuxiu62/atropos/internal/ipv4"
	"github.com/xiuxiu62/atropos/internal/tcp"
	"github.com/xiuxiu62/atropos/internal/tun"
	"github.com/xiuxiu62/atropos/internal/udp"
)

type Stack struct {
	dev    tun.Device
	addr   [4]byte
	udpTbl udp.Table
	tcpTbl tcp.Table
}

func New(device tun.Device, address [4]byte) *Stack {
	s := &Stack{dev: device, addr: address}
	s.udpTbl.Init(s)
	s.tcpTbl.Init(s)
	return s
}

func (s *Stack) SendUDP(srcAddr, dstAddr [4]byte, srcPort, dstPort uint16, payload []byte) error {
	seg := udp.Serialize(srcAddr, dstAddr, srcPort, dstPort, payload)
	packet := ipv4.Serialize(srcAddr, dstAddr, ipv4.ProtoUDP, 64, seg)
	_, err := s.dev.Write(packet)
	return err
}

// SendTCP implements tcp.Sender.
func (s *Stack) SendTCP(srcAddr, dstAddr [4]byte, seg tcp.Segment) error {
	segBytes := tcp.Serialize(srcAddr, dstAddr, seg)
	packet := ipv4.Serialize(srcAddr, dstAddr, ipv4.ProtoTCP, 64, segBytes)
	_, err := s.dev.Write(packet)
	return err
}

func (s *Stack) UDP() *udp.Table { return &s.udpTbl }
func (s *Stack) TCP() *tcp.Table { return &s.tcpTbl }

func (s *Stack) DialTCP(localPort uint16, remoteAddr [4]byte, remotePort uint16) (*tcp.Connection, error) {
	return s.tcpTbl.Dial(s.addr, remoteAddr, localPort, remotePort)
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
		seg, err := tcp.Parse(hdr.Payload)
		if err != nil {
			return fmt.Errorf("tcp parse: %w", err)
		}
		s.tcpTbl.Deliver(hdr.Src, hdr.Dst, seg)
		return nil
	default:
		return nil
	}
}

func (s *Stack) handleICMP(hdr ipv4.Header) error {
	msg, err := icmp.Parse(hdr.Payload)
	if err != nil {
		return fmt.Errorf("icmp parse: %w", err)
	}
	if msg.Type != icmp.TypeEchoRequest {
		return nil
	}

	reply := icmp.EchoReply(msg)
	packet := ipv4.Serialize(s.addr, hdr.Src, ipv4.ProtoICMP, 64, reply)

	_, err = s.dev.Write(packet)
	if err != nil {
		return fmt.Errorf("writing reply: %w", err)
	}
	return nil
}
