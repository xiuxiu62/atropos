package vwire

import (
	"errors"
	"sync"

	"github.com/xiuxiu62/atropos/internal/tun"
)

type endpoint struct {
	name   string
	inbox  chan []byte
	peer   *endpoint
	guard  sync.Mutex
	closed bool
}

func Pair(nameA, nameB string) (a, b tun.Device) {
	ea := &endpoint{name: nameA, inbox: make(chan []byte, 256)}
	eb := &endpoint{name: nameB, inbox: make(chan []byte, 256)}
	ea.peer = eb
	eb.peer = ea
	return ea, eb
}

func (e *endpoint) Read(buf []byte) (int, error) {
	data, ok := <-e.inbox
	if !ok {
		return 0, errors.New("vwire: endpoint closed")
	}
	n := copy(buf, data)
	return n, nil
}

func (e *endpoint) Write(buf []byte) (int, error) {
	e.guard.Lock()
	closed := e.closed
	e.guard.Unlock()
	if closed {
		return 0, errors.New("vwire: endpoint closed")
	}

	cpy := make([]byte, len(buf))
	copy(cpy, buf)

	select {
	case e.peer.inbox <- cpy:
		return len(buf), nil
	default:
		return 0, errors.New("vwire: peer inbox full")
	}
}

func (e *endpoint) Close() error {
	e.guard.Lock()
	defer e.guard.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	close(e.inbox)
	return nil
}

func (e *endpoint) Name() string { return e.name }
