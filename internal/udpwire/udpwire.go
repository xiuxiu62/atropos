package udpwire

import (
	"fmt"
	"net"

	"github.com/xiuxiu62/atropos/internal/tun"
)

type Device struct {
	conn     *net.UDPConn
	peerAddr *net.UDPAddr
	name     string
}

func Open(name, localAddr, peerAddr string) (*Device, error) {
	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("udpwire: resolving local addr %q: %w", localAddr, err)
	}
	raddr, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return nil, fmt.Errorf("udpwire: resolving peer addr %q: %w", peerAddr, err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, fmt.Errorf("udpwire: listening on %q: %w", localAddr, err)
	}
	return &Device{conn: conn, peerAddr: raddr, name: name}, nil
}

func (d *Device) Read(buf []byte) (int, error) {
	n, _, err := d.conn.ReadFromUDP(buf)
	return n, err
}

func (d *Device) Write(buf []byte) (int, error) {
	return d.conn.WriteToUDP(buf, d.peerAddr)
}

func (d *Device) Close() error { return d.conn.Close() }

func (d *Device) Name() string { return d.name }

var _ tun.Device = (*Device)(nil)
