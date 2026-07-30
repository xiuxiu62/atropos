package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/xiuxiu62/atropos/internal/stack"
	"github.com/xiuxiu62/atropos/internal/tun"
)

func main() {
	dev, err := tun.Open(tun.Descriptor{Name: "tun0", CIDR: "10.0.0.1/24"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	defer dev.Close()

	s := stack.Create(dev, [4]byte{10, 0, 0, 1})

	// graceful teardown on Ctrl+C so the adapter doesn't linger
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nshutting down...")
		dev.Close()
		os.Exit(0)
	}()

	// UDP echo socket on port 9999 — proves the UDP path end-to-end
	sock, err := s.UDP().Bind(9999)
	if err != nil {
		log.Fatalf("binding udp socket: %v", err)
	}
	go func() {
		for {
			pkt := sock.Recv()
			fmt.Printf("udp: got %q from %v:%d (to %v)\n", pkt.Data, pkt.SrcAddr, pkt.SrcPort, pkt.DstAddr)
			if err := s.SendUDP(pkt.DstAddr, pkt.SrcAddr, 9999, pkt.SrcPort, pkt.Data); err != nil {
				log.Printf("udp echo reply failed: %v", err)
			}
		}
	}()

	fmt.Println("atropos up on tun0 (10.0.0.1), waiting for packets...")
	if err := s.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
