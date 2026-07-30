//go:build windows

package tun

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wintunDLL = windows.NewLazyDLL("wintun.dll")

	createAdapter        = wintunDLL.NewProc("WintunCreateAdapter")
	closeAdapter         = wintunDLL.NewProc("WintunCloseAdapter")
	startSession         = wintunDLL.NewProc("WintunStartSession")
	endSession           = wintunDLL.NewProc("WintunEndSession")
	getReadWaitEvent     = wintunDLL.NewProc("WintunGetReadWaitEvent")
	receivePacket        = wintunDLL.NewProc("WintunReceivePacket")
	releaseReceivePacket = wintunDLL.NewProc("WintunReleaseReceivePacket")
	allocateSendPacket   = wintunDLL.NewProc("WintunAllocateSendPacket")
	sendPacket           = wintunDLL.NewProc("WintunSendPacket")
)

const ringCapacity = 0x400000

type windowsDevice struct {
	adapter    uintptr
	session    uintptr
	readEvent  windows.Handle
	name       string
	guard      sync.Mutex
	closed     atomic.Bool
	exitOnce   sync.Once
	readExited chan struct{}
}

func open(desc Descriptor) (Device, error) {
	if err := wintunDLL.Load(); err != nil {
		return nil, fmt.Errorf("tun: loading wintun.dll: %w (place wintun.dll next to the executable — download from https://www.wintun.net)", err)
	}

	namePtr, err := windows.UTF16PtrFromString(desc.Name)
	if err != nil {
		return nil, fmt.Errorf("tun: invalid adapter name: %w", err)
	}
	tunnelTypePtr, err := windows.UTF16PtrFromString("Netstack")
	if err != nil {
		return nil, err
	}

	adapter, _, callErr := createAdapter.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(tunnelTypePtr)),
		0,
	)
	if adapter == 0 {
		return nil, fmt.Errorf("tun: WintunCreateAdapter failed: %w", callErr)
	}

	session, _, callErr := startSession.Call(adapter, uintptr(ringCapacity))
	if session == 0 {
		closeAdapter.Call(adapter)
		return nil, fmt.Errorf("tun: WintunStartSession failed: %w", callErr)
	}

	eventHandle, _, _ := getReadWaitEvent.Call(session)

	dev := &windowsDevice{
		adapter:    adapter,
		session:    session,
		readEvent:  windows.Handle(eventHandle),
		name:       desc.Name,
		readExited: make(chan struct{}),
	}

	if err := configureInterface(desc.Name, desc.CIDR); err != nil {
		dev.Close()
		return nil, err
	}

	return dev, nil
}

func configureInterface(name, cidr string) error {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("tun: invalid CIDR %q: %w", cidr, err)
	}
	mask := net.IP(ipNet.Mask).String()

	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=%s", name), "static", ip.String(), mask)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netsh set address: %w (%s)", err, out)
	}
	return nil
}

// Read polls with a bounded wait rather than blocking forever, so it can
// notice Close() asking it to stop instead of racing the teardown of the
// session/adapter handles it's actively using.
func (d *windowsDevice) Read(buf []byte) (int, error) {
	for {
		if d.closed.Load() {
			d.exitOnce.Do(func() { close(d.readExited) })
			return 0, io.EOF
		}

		var packetSize uint32
		packetPtr, _, callErr := receivePacket.Call(d.session, uintptr(unsafe.Pointer(&packetSize)))
		if packetPtr != 0 {
			n := copy(buf, unsafe.Slice((*byte)(unsafe.Pointer(packetPtr)), packetSize))
			releaseReceivePacket.Call(d.session, packetPtr)
			return n, nil
		}

		errno, ok := callErr.(syscall.Errno)
		if !ok || errno != windows.ERROR_NO_MORE_ITEMS {
			if d.closed.Load() {
				d.exitOnce.Do(func() { close(d.readExited) })
				return 0, io.EOF
			}
			return 0, fmt.Errorf("tun: WintunReceivePacket: %w", callErr)
		}

		if _, err := windows.WaitForSingleObject(d.readEvent, 500); err != nil && err != windows.WAIT_TIMEOUT {
			return 0, fmt.Errorf("tun: WaitForSingleObject: %w", err)
		}
	}
}

func (d *windowsDevice) Write(buf []byte) (int, error) {
	d.guard.Lock()
	defer d.guard.Unlock()

	packetPtr, _, callErr := allocateSendPacket.Call(d.session, uintptr(len(buf)))
	if packetPtr == 0 {
		return 0, fmt.Errorf("tun: WintunAllocateSendPacket: %w", callErr)
	}

	dst := unsafe.Slice((*byte)(unsafe.Pointer(packetPtr)), len(buf))
	copy(dst, buf)
	sendPacket.Call(d.session, packetPtr)

	return len(buf), nil
}

// Close signals Read to stop, waits for it to actually exit, and only then
// tears down the session/adapter — avoiding the race that crashed before.
func (d *windowsDevice) Close() error {
	if !d.closed.CompareAndSwap(false, true) {
		return nil
	}

	select {
	case <-d.readExited:
	case <-time.After(2 * time.Second):
	}

	d.guard.Lock()
	defer d.guard.Unlock()
	if d.session != 0 {
		endSession.Call(d.session)
		d.session = 0
	}
	if d.adapter != 0 {
		closeAdapter.Call(d.adapter)
		d.adapter = 0
	}
	return nil
}

func (d *windowsDevice) Name() string { return d.name }
