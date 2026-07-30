package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/xiuxiu62/atropos/internal/stack"
	"github.com/xiuxiu62/atropos/internal/udpwire"
)

func main() {
	local := flag.String("local", "", "local UDP address to bind, e.g. :9000 (required)")
	peer := flag.String("peer", "", "remote peer UDP address, e.g. 192.168.1.50:9000 (required)")
	addr := flag.String("addr", "10.0.0.1", "synthetic IPv4 address this stack answers to")
	dial := flag.String("dial", "", "synthetic addr:port to actively connect to over TCP after startup, e.g. 10.0.0.2:7777")
	message := flag.String("msg", "hello from atropos", "message to send if -dial is set")
	flag.Parse()

	if *local == "" || *peer == "" {
		fmt.Fprintln(os.Stderr, "usage: atropos -local :9000 -peer <host>:9001 -addr 10.0.0.1 [-dial 10.0.0.2:7777]")
		os.Exit(1)
	}

	synthAddr, err := parseV4(*addr)
	if err != nil {
		log.Fatalf("invalid -addr %q: %v", *addr, err)
	}

	dev, err := udpwire.Open("udpwire0", *local, *peer)
	if err != nil {
		log.Fatalf("udpwire: %v", err)
	}
	defer dev.Close()

	s := stack.New(dev, synthAddr)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nshutting down...")
		dev.Close()
		os.Exit(0)
	}()

	// Always run a TCP echo listener on 7777, same as before — this is
	// what a -dial from the peer instance will talk to.
	listener, err := s.TCP().Listen(7777)
	if err != nil {
		log.Fatalf("tcp listen: %v", err)
	}
	go func() {
		for {
			conn := listener.Accept()
			fmt.Println("tcp: connection accepted")
			go func() {
				for {
					data, ok := conn.Read()
					if !ok {
						fmt.Println("tcp: connection closed by peer")
						return
					}
					fmt.Printf("tcp: got %q, echoing\n", data)
					conn.Write(data)
				}
			}()
		}
	}()

	go s.Run() // Run blocks, so this instance keeps serving while we optionally dial below

	fmt.Printf("atropos up over udpwire — local UDP %s, peer %s, synthetic addr %s\n", *local, *peer, *addr)

	if *dial != "" {
		runDial(s, *dial, *message)
	}

	select {} // block forever; Ctrl+C handled by the signal goroutine above
}

// runDial actively connects to a peer's synthetic addr:port, sends a
// message, prints whatever comes back, then closes — a CLI-driven way
// to exercise the client side of the handshake against a real remote
// atropos instance, the same path Dial takes in the harness test.
func runDial(s *stack.Stack, target, message string) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		log.Fatalf("invalid -dial target %q: %v", target, err)
	}
	remoteAddr, err := parseV4(host)
	if err != nil {
		log.Fatalf("invalid -dial host %q: %v", host, err)
	}
	var remotePort uint16
	if _, err := fmt.Sscanf(portStr, "%d", &remotePort); err != nil {
		log.Fatalf("invalid -dial port %q: %v", portStr, err)
	}

	conn, err := s.DialTCP(54321, remoteAddr, remotePort)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	fmt.Printf("dial: connected to %s\n", target)

	if _, err := conn.Write([]byte(message)); err != nil {
		log.Fatalf("dial: write: %v", err)
	}

	data, ok := conn.Read()
	if !ok {
		log.Fatal("dial: connection closed before echo arrived")
	}
	fmt.Printf("dial: received echo: %q\n", data)

	conn.Close()
}

func parseV4(s string) ([4]byte, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return [4]byte{}, fmt.Errorf("not a valid IP: %s", s)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return [4]byte{}, fmt.Errorf("not an IPv4 address: %s", s)
	}
	return [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}, nil
}
