package ipv4

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/xiuxiu62/atropos/internal/checksum"
)

const (
	MinHeaderLen = 20
	Version      = 4
)

const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
)

var ErrPacketTooShort = errors.New("ipv4: packet shorter than header claims")

type Header struct {
	Version    uint8
	IHL        uint8
	TOS        uint8
	TotalLen   uint16
	ID         uint16
	Flags      uint8
	FragOffset uint16
	TTL        uint8
	Protocol   uint8
	Checksum   uint16
	Src        [4]byte
	Dst        [4]byte
	Payload    []byte
}

func Parse(buf []byte) (Header, error) {
	if len(buf) < MinHeaderLen {
		return Header{}, fmt.Errorf("%w: got %d bytes", ErrPacketTooShort, len(buf))
	}

	h := Header{
		Version:  buf[0] >> 4,
		IHL:      buf[0] & 0x0f,
		TOS:      buf[1],
		TotalLen: binary.BigEndian.Uint16(buf[2:4]),
		ID:       binary.BigEndian.Uint16(buf[4:6]),
		TTL:      buf[8],
		Protocol: buf[9],
		Checksum: binary.BigEndian.Uint16(buf[10:12]),
	}

	flagsFrag := binary.BigEndian.Uint16(buf[6:8])
	h.Flags = uint8(flagsFrag >> 13)
	h.FragOffset = flagsFrag & 0x1fff

	copy(h.Src[:], buf[12:16])
	copy(h.Dst[:], buf[16:20])

	headerLen := int(h.IHL) * 4
	if headerLen < MinHeaderLen {
		return Header{}, fmt.Errorf("ipv4: invalid IHL %d", h.IHL)
	}
	if len(buf) < headerLen {
		return Header{}, fmt.Errorf("%w: header claims %d bytes, got %d", ErrPacketTooShort, headerLen, len(buf))
	}
	if int(h.TotalLen) > len(buf) {
		return Header{}, fmt.Errorf("%w: total length %d exceeds buffer %d", ErrPacketTooShort, h.TotalLen, len(buf))
	}

	h.Payload = buf[headerLen:h.TotalLen]
	return h, nil
}

func Serialize(src, dst [4]byte, protocol, ttl uint8, payload []byte) []byte {
	totalLen := MinHeaderLen + len(payload)
	buf := make([]byte, totalLen)

	buf[0] = (Version << 4) | (MinHeaderLen / 4) // version=4, IHL=5
	buf[1] = 0                                   // TOS
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(buf[4:6], 0) // ID — fine to leave 0 for unfragmented traffic
	binary.BigEndian.PutUint16(buf[6:8], 0) // flags/fragment offset — no fragmentation
	buf[8] = ttl
	buf[9] = protocol
	binary.BigEndian.PutUint16(buf[10:12], 0) // checksum placeholder
	copy(buf[12:16], src[:])
	copy(buf[16:20], dst[:])
	copy(buf[MinHeaderLen:], payload)

	csum := checksum.RFC1071(buf[:MinHeaderLen])
	binary.BigEndian.PutUint16(buf[10:12], csum)

	return buf
}
