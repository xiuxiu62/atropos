package tcp

import (
	"fmt"
	"math/rand/v2"
	"sync"
)

type State int32

const recvWindow = 65535

const (
	StateListen State = iota
	StateSynSent
	StateSynRcvd
	StateEstablished
	StateCloseWait
	StateLastAck
	StateClosed
)

func (s State) String() string {
	switch s {
	case StateListen:
		return "LISTEN"
	case StateSynRcvd:
		return "SYN_RCVD"
	case StateEstablished:
		return "ESTABLISHED"
	case StateCloseWait:
		return "CLOSE_WAIT"
	case StateLastAck:
		return "LAST_ACK"
	case StateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

type Sender interface {
	SendTCP(srcAddr, dstAddr [4]byte, seg Segment) error
}

type Connection struct {
	localAddr, remoteAddr [4]byte
	localPort, remotePort uint16
	sender                Sender

	guard  sync.Mutex
	state  State
	sndNxt uint32
	sndUna uint32
	rcvNxt uint32

	inbox  chan []byte
	closed bool
}

func create(localAddr, remoteAddr [4]byte, localPort, remotePort uint16, sender Sender) Connection {
	return Connection{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		localPort:  localPort,
		remotePort: remotePort,
		sender:     sender,
		inbox:      make(chan []byte, 64),
	}
}

func (c *Connection) Read() (data []byte, ok bool) {
	data, ok = <-c.inbox
	return
}

func (c *Connection) Write(data []byte) (int, error) {
	c.guard.Lock()
	if c.state != StateEstablished {
		c.guard.Unlock()
		return 0, fmt.Errorf("tcp: write on non-established connection (state=%s)", c.state)
	}
	seg := Segment{
		SrcPort: c.localPort,
		DstPort: c.remotePort,
		SeqNum:  c.sndNxt,
		AckNum:  c.rcvNxt,
		Flags:   FlagACK | FlagPSH,
		Window:  recvWindow,
		Payload: data,
	}
	c.guard.Unlock()

	if err := c.sender.SendTCP(c.localAddr, c.remoteAddr, seg); err != nil {
		return 0, err
	}

	c.guard.Lock()
	c.sndNxt += uint32(len(data))
	c.guard.Unlock()
	return len(data), nil
}

func (c *Connection) Close() error {
	c.guard.Lock()
	if c.closed {
		c.guard.Unlock()
		return nil
	}
	c.closed = true
	seg := Segment{
		SrcPort: c.localPort,
		DstPort: c.remotePort,
		SeqNum:  c.sndNxt,
		AckNum:  c.rcvNxt,
		Flags:   FlagFIN | FlagACK,
		Window:  recvWindow,
	}
	c.state = StateLastAck
	c.guard.Unlock()

	c.sndNxt++ // FIN consumes one sequence number
	return c.sender.SendTCP(c.localAddr, c.remoteAddr, seg)
}

func (c *Connection) State() State {
	c.guard.Lock()
	defer c.guard.Unlock()
	return c.state
}

func randomISN() uint32 {
	return rand.Uint32()
}
