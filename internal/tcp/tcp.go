package tcp

import (
	"encoding/binary"
	"fmt"

	"github.com/xiuxiu62/atropos/internal/ipv4"
)

const (
	MinHeaderLen   = 20
	ProtocolNumber = ipv4.ProtoTCP

	FlagFIN uint8 = 1 << 0
	FlagSYN uint8 = 1 << 1
	FlagRST uint8 = 1 << 2
	FlagPSH uint8 = 1 << 3
	FlagACK uint8 = 1 << 4
	FlagURG uint8 = 1 << 5
)

type Segment struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	Urgent     uint16
	Payload    []byte
}

func (s Segment) HasFlag(f uint8) bool { return s.Flags&f != 0 }

func Parse(buf []byte) (Segment, error) {
	if len(buf) < MinHeaderLen {
		return Segment{}, fmt.Errorf("tcp: segment too short: %d bytes", len(buf))
	}

	s := Segment{
		SrcPort: binary.BigEndian.Uint16(buf[0:2]),
		DstPort: binary.BigEndian.Uint16(buf[2:4]),
		SeqNum:  binary.BigEndian.Uint32(buf[4:8]),
		AckNum:  binary.BigEndian.Uint32(buf[8:12]),
	}

	s.DataOffset = buf[12] >> 4
	s.Flags = buf[13]
	s.Window = binary.BigEndian.Uint16(buf[14:16])
	s.Checksum = binary.BigEndian.Uint16(buf[16:18])
	s.Urgent = binary.BigEndian.Uint16(buf[18:20])

	headerLen := int(s.DataOffset) * 4
	if headerLen < MinHeaderLen {
		return Segment{}, fmt.Errorf("tcp: invalid data offset %d", s.DataOffset)
	}
	if len(buf) < headerLen {
		return Segment{}, fmt.Errorf("tcp: header claims %d bytes, got %d", headerLen, len(buf))
	}

	s.Payload = buf[headerLen:]
	return s, nil
}
