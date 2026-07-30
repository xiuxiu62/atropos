package tcp

import (
	"fmt"
	"sync"
)

type connKey struct {
	remoteAddr [4]byte
	remotePort uint16
	localPort  uint16
}

type Listener struct {
	port   uint16
	accept chan *Connection
}

func (l *Listener) Accept() *Connection {
	return <-l.accept
}

type Table struct {
	guard     sync.Mutex
	listeners map[uint16]*Listener
	conns     map[connKey]*Connection
	sender    Sender
}

func (t *Table) Init(sender Sender) {
	t.listeners = make(map[uint16]*Listener)
	t.conns = make(map[connKey]*Connection)
	t.sender = sender
}

func (t *Table) Listen(port uint16) (*Listener, error) {
	t.guard.Lock()
	defer t.guard.Unlock()

	if _, exists := t.listeners[port]; exists {
		return nil, fmt.Errorf("tcp: port %d already listening", port)
	}
	l := &Listener{port: port, accept: make(chan *Connection, 16)}
	t.listeners[port] = l
	return l, nil
}

func (t *Table) Deliver(srcAddr, dstAddr [4]byte, seg Segment) {
	key := connKey{remoteAddr: srcAddr, remotePort: seg.SrcPort, localPort: seg.DstPort}

	t.guard.Lock()
	conn, exists := t.conns[key]
	t.guard.Unlock()

	if exists {
		t.deliverToConnection(conn, seg)
		return
	}

	if seg.HasFlag(FlagSYN) && !seg.HasFlag(FlagACK) {
		t.handleSYN(srcAddr, dstAddr, seg, key)
		return
	}
}

func (t *Table) handleSYN(srcAddr, dstAddr [4]byte, seg Segment, key connKey) {
	t.guard.Lock()
	listener, ok := t.listeners[seg.DstPort]
	t.guard.Unlock()
	if !ok {
		return
	}

	conn := create(dstAddr, srcAddr, seg.DstPort, seg.SrcPort, t.sender)
	conn.guard.Lock()
	conn.state = StateSynRcvd
	conn.rcvNxt = seg.SeqNum + 1
	conn.sndNxt = randomISN()
	iss := conn.sndNxt
	conn.guard.Unlock()

	t.guard.Lock()
	t.conns[key] = &conn
	t.guard.Unlock()

	synAck := Segment{
		SrcPort: seg.DstPort,
		DstPort: seg.SrcPort,
		SeqNum:  iss,
		AckNum:  conn.rcvNxt,
		Flags:   FlagSYN | FlagACK,
		Window:  recvWindow,
	}
	conn.sender.SendTCP(dstAddr, srcAddr, synAck)

	conn.guard.Lock()
	conn.sndNxt++
	conn.guard.Unlock()

	_ = listener
}

func (t *Table) deliverToConnection(conn *Connection, seg Segment) {
	conn.guard.Lock()
	state := conn.state
	conn.guard.Unlock()

	switch state {
	case StateSynSent:
		if seg.HasFlag(FlagSYN) && seg.HasFlag(FlagACK) {
			conn.guard.Lock()
			conn.rcvNxt = seg.SeqNum + 1
			conn.state = StateEstablished
			conn.guard.Unlock()

			ack := Segment{
				SrcPort: conn.localPort, DstPort: conn.remotePort,
				SeqNum: conn.sndNxt, AckNum: conn.rcvNxt,
				Flags: FlagACK, Window: recvWindow,
			}
			conn.sender.SendTCP(conn.localAddr, conn.remoteAddr, ack)
		}
	case StateSynRcvd:
		if seg.HasFlag(FlagACK) {
			conn.guard.Lock()
			conn.state = StateEstablished
			conn.guard.Unlock()

			t.guard.Lock()
			listener := t.listeners[conn.localPort]
			t.guard.Unlock()
			if listener != nil {
				select {
				case listener.accept <- conn:
				default:
				}
			}
		}

	case StateEstablished:
		t.handleEstablished(conn, seg)

	case StateLastAck:
		if seg.HasFlag(FlagACK) {
			t.retireConnection(conn)
		}
	}
}

func (t *Table) handleEstablished(conn *Connection, seg Segment) {
	conn.guard.Lock()

	if len(seg.Payload) > 0 {
		conn.rcvNxt += uint32(len(seg.Payload))
		conn.guard.Unlock()

		select {
		case conn.inbox <- seg.Payload:
		default:
		}

		ack := Segment{
			SrcPort: conn.localPort, DstPort: conn.remotePort,
			SeqNum: conn.sndNxt, AckNum: conn.rcvNxt,
			Flags: FlagACK, Window: recvWindow,
		}
		conn.sender.SendTCP(conn.localAddr, conn.remoteAddr, ack)
		conn.guard.Lock()
	}

	if seg.HasFlag(FlagFIN) {
		conn.rcvNxt++
		conn.state = StateCloseWait
		closeAck := Segment{
			SrcPort: conn.localPort, DstPort: conn.remotePort,
			SeqNum: conn.sndNxt, AckNum: conn.rcvNxt,
			Flags: FlagFIN | FlagACK, Window: recvWindow,
		}
		conn.state = StateLastAck
		sndNxtAfterFin := conn.sndNxt + 1
		conn.guard.Unlock()

		close(conn.inbox)
		conn.sender.SendTCP(conn.localAddr, conn.remoteAddr, closeAck)

		conn.guard.Lock()
		conn.sndNxt = sndNxtAfterFin
	}

	conn.guard.Unlock()
}

func (t *Table) retireConnection(conn *Connection) {
	conn.guard.Lock()
	conn.state = StateClosed
	conn.guard.Unlock()

	key := connKey{remoteAddr: conn.remoteAddr, remotePort: conn.remotePort, localPort: conn.localPort}
	t.guard.Lock()
	delete(t.conns, key)
	t.guard.Unlock()
}
