// main.go
package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf loadbalancer.bpf.c

func ipToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		log.Fatalf("Invalid IPv4: %s", ipStr)
	}
	return binary.LittleEndian.Uint32(ip)
}

func intToIP(ipUint uint32) string {
	ipBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipBytes, ipUint)
	return net.IP(ipBytes).String()
}

func portToStr(port uint16) string {
	portBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(portBytes, port)
	return fmt.Sprintf("%d", binary.BigEndian.Uint16(portBytes))
}

func tcpStateToString(state uint8) string {
	switch state {
	case 0:
		return "CLOSED"
	case 1:
		return "SYN_SENT"
	case 2:
		return "ESTABLISHED"
	case 3:
		return "HALF_CLOSED"
	case 4:
		return "TIME_WAIT"
	default:
		return "UNKNOWN"
	}
}

func checkHealth(ip string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func main() {
	// Load compiled BPF object

	iface, err := net.InterfaceByName("eno1")
	if err != nil {
		log.Fatalf("failed to get interface eth0: %v", err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.LbTc,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("failed to attach TC program: %v", err)
	}
	defer l.Close()

	// Define backend endpoints
	backendList := []struct {
		IP   string
		Port int
	}{
		{"192.168.1.82", 31081},
		//{"192.168.1.83", 31081},
		//{"192.168.1.84", 31081},
	}

	for _, b := range backendList {
		alive := checkHealth(b.IP, b.Port)
		if !alive {
			log.Printf("Backend %s:%d is down, skipping...", b.IP, b.Port)
			continue
		}
		e := bpfEndpoint{
			Ip:      ipToUint32(b.IP),
			Port:    uint16(b.Port),
			Alive:   boolToUint8(alive),
			Ifindex: uint8(iface.Index),
		}
		endpoints := objs.Endpoints
		if err := endpoints.Put(ipToUint32(b.IP), e); err != nil {
			log.Printf("failed to update endpoint %s: %v", b.IP, err)
		}
	}

	// Context for shutdown
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		cancel()
	}()

	log.Println("Starting health check loop...")
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Shutting down...")
			return
		case <-ticker.C:
			// clear stdout
			fmt.Print("\033[H\033[2J")
			tcpStateIter := objs.TcpStateMap.Iterate()
			bpfTuple := bpfTuple{}
			bpfTcpState := bpfTcpState{}
			for tcpStateIter.Next(&bpfTuple, &bpfTcpState) {
				log.Printf("%s:%s -> %s:%s state=%s (last_ack: %d)\n",
					intToIP(bpfTuple.SrcIp), portToStr(bpfTuple.SrcPort),
					intToIP(bpfTuple.DstIp), portToStr(bpfTuple.DstPort),
					tcpStateToString(bpfTcpState.TcpState), bpfTcpState.LastAckTime)
			}
		}
	}
}

func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
