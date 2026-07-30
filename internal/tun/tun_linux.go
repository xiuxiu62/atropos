//go:build linux

package tun

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

const (
	ifNameSize = 16
	tunPath    = "/dev/net/tun"

	iffTUN   = 0x0001
	iffNoPI  = 0x1000
	tunSetIF = 0x400454ca
)

type ifReq struct {
	Name  [ifNameSize]byte
	Flags uint16
	pad   [22]byte
}

type linuxDevice struct {
	file *os.File
	name string
}

func open(desc Descriptor) (Device, error) {
	fd, err := syscall.Open(tunPath, syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", tunPath, err)
	}

	var req ifReq
	copy(req.Name[:], desc.Name)
	req.Flags = iffTUN | iffNoPI

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(tunSetIF),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF: %w", errno)
	}

	dev := &linuxDevice{
		file: os.NewFile(uintptr(fd), tunPath),
		name: desc.Name,
	}

	if err := configureInterface(desc.Name, desc.CIDR); err != nil {
		dev.Close()
		return nil, err
	}

	return dev, nil
}

func configureInterface(name, cidr string) error {
	if err := exec.Command("ip", "addr", "add", cidr, "dev", name).Run(); err != nil {
		return fmt.Errorf("assigning address: %w", err)
	}
	if err := exec.Command("ip", "link", "set", "dev", name, "up").Run(); err != nil {
		return fmt.Errorf("bringing interface up: %w", err)
	}
	return nil
}

func (d *linuxDevice) Read(buf []byte) (int, error)  { return d.file.Read(buf) }
func (d *linuxDevice) Write(buf []byte) (int, error) { return d.file.Write(buf) }
func (d *linuxDevice) Close() error                  { return d.file.Close() }
func (d *linuxDevice) Name() string                  { return d.name }
