package tcp

import (
	"fmt"
	"time"
)

func (t *Table) Dial(localAddr, remoteAddr [4]byte, localPort, remotePort uint16) (*Connection, error) {
	key := connKey{remoteAddr: remoteAddr, remotePort: remotePort, localPort: localPort}

	conn := create(localAddr, remoteAddr, localPort, remotePort, t.sender)
	conn.guard.Lock()
	conn.state = StateSynSent
	conn.sndNxt = randomISN()
	iss := conn.sndNxt
	conn.guard.Unlock()

	t.guard.Lock()
	t.conns[key] = &conn
	t.guard.Unlock()

	syn := Segment{
		SrcPort: localPort,
		DstPort: remotePort,
		SeqNum:  iss,
		Flags:   FlagSYN,
		Window:  recvWindow,
	}
	if err := t.sender.SendTCP(localAddr, remoteAddr, syn); err != nil {
		return nil, fmt.Errorf("tcp: sending SYN: %w", err)
	}

	conn.guard.Lock()
	conn.sndNxt++ // SYN consumes a sequence number
	conn.guard.Unlock()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if conn.State() == StateEstablished {
			return &conn, nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return nil, fmt.Errorf("tcp: handshake with %v:%d timed out", remoteAddr, remotePort)
}
