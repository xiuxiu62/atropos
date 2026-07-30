package udp

import (
	"fmt"
	"sync"
)

type Packet struct {
	SrcAddr [4]byte
	SrcPort uint16
	DstAddr [4]byte
	Data    []byte
}

type Socket struct {
	port  uint16
	inbox chan Packet
}

type Sender interface {
	SendUDP(srcAddr, dstAddr [4]byte, srcPort, dstPort uint16, payload []byte) error
}

type Table struct {
	guard   sync.Mutex
	sockets map[uint16]*Socket
	sender  Sender
}

func (table *Table) Init(sender Sender) {
	table.sockets = make(map[uint16]*Socket)
	table.sender = sender
}

func (t *Table) Bind(port uint16) (*Socket, error) {
	t.guard.Lock()
	defer t.guard.Unlock()

	if _, exists := t.sockets[port]; exists {
		return nil, fmt.Errorf("udp: port %d already in use", port)
	}

	s := &Socket{port: port, inbox: make(chan Packet, 64)}
	t.sockets[port] = s
	return s, nil
}

func (t *Table) Deliver(srcAddr, dstAddr [4]byte, seg Segment) {
	t.guard.Lock()
	sock, ok := t.sockets[seg.DstPort]
	t.guard.Unlock()
	if !ok { // no listener
		return
	}

	select {
	case sock.inbox <- Packet{
		SrcAddr: srcAddr,
		SrcPort: seg.SrcPort,
		DstAddr: dstAddr,
		Data:    seg.Payload,
	}:
	default: // drop, inbox is full
	}
}

func (s *Socket) Recv() Packet {
	return <-s.inbox
}

func (t *Table) Close(port uint16) {
	t.guard.Lock()
	defer t.guard.Unlock()
	if sock, ok := t.sockets[port]; ok {
		close(sock.inbox)
		delete(t.sockets, port)
	}
}
