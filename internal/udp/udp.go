package udp

import (
	"encoding/binary"
	"fmt"

	"github.com/xiuxiu62/atropos/internal/checksum"
	"github.com/xiuxiu62/atropos/internal/ipv4"
)

const (
	HeaderLen      = 8
	ProtocolNumber = ipv4.ProtoUDP
)

type Segment struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
	Payload  []byte
}

func Parse(buf []byte) (Segment, error) {
	if len(buf) < HeaderLen {
		return Segment{}, fmt.Errorf("udp: segment too short: %d bytes", len(buf))
	}
	length := binary.BigEndian.Uint16(buf[4:6])
	if int(length) > len(buf) {
		return Segment{}, fmt.Errorf("udp: length %d exceeds buffer %d", length, len(buf))
	}
	return Segment{
		SrcPort:  binary.BigEndian.Uint16(buf[0:2]),
		DstPort:  binary.BigEndian.Uint16(buf[2:4]),
		Length:   length,
		Checksum: binary.BigEndian.Uint16(buf[6:8]),
		Payload:  buf[HeaderLen:length],
	}, nil
}

func Serialize(src, dst [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	length := uint16(HeaderLen + len(payload))
	buf := make([]byte, length)

	binary.BigEndian.PutUint16(buf[0:2], srcPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	binary.BigEndian.PutUint16(buf[4:6], length)
	binary.BigEndian.PutUint16(buf[6:8], 0) // checksum placeholder
	copy(buf[HeaderLen:], payload)

	partial := checksum.PseudoHeaderSum(src, dst, ProtocolNumber, length)
	csum := checksum.SumWithPseudo(partial, buf)
	// RFC 768: an all-zero checksum means "no checksum computed" — if
	// the real computed value is 0, transmit all-ones instead so it's
	// not misread as absent.
	if csum == 0 {
		csum = 0xffff
	}
	binary.BigEndian.PutUint16(buf[6:8], csum)

	return buf
}
