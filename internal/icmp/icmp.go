package icmp

import (
	"encoding/binary"
	"fmt"

	"github.com/xiuxiu62/atropos/internal/checksum"
)

const (
	TypeEchoReply   = 0
	TypeEchoRequest = 8

	headerLen = 8
)

type Message struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	ID       uint16
	Seq      uint16
	Data     []byte
}

func Parse(buf []byte) (Message, error) {
	if len(buf) < headerLen {
		return Message{}, fmt.Errorf("icmp: packet too short: %d bytes", len(buf))
	}
	return Message{
		Type:     buf[0],
		Code:     buf[1],
		Checksum: binary.BigEndian.Uint16(buf[2:4]),
		ID:       binary.BigEndian.Uint16(buf[4:6]),
		Seq:      binary.BigEndian.Uint16(buf[6:8]),
		Data:     buf[headerLen:],
	}, nil
}

func EchoReply(req Message) []byte {
	buf := make([]byte, headerLen+len(req.Data))
	buf[0] = TypeEchoReply
	buf[1] = 0
	binary.BigEndian.PutUint16(buf[4:6], req.ID)
	binary.BigEndian.PutUint16(buf[6:8], req.Seq)
	copy(buf[headerLen:], req.Data)

	csum := checksum.RFC1071(buf)
	binary.BigEndian.PutUint16(buf[2:4], csum)
	return buf
}
