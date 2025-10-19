// main.go
package main

import (
	"context"
	"loadbalancer/internal/loadbalancer"
	"net"
	"os"
	"os/signal"
	"syscall"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux lb bpf/lb.bpf.c

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		cancel()
	}()

	rrp := loadbalancer.NewRoundRobinPool()
	rrp.Register(&loadbalancer.Endpoint{
		IP:       net.ParseIP("192.168.1.82"),
		Port:     31080,
		Protocol: "tcp",
	})
	rrp.Register(&loadbalancer.Endpoint{
		IP:       net.ParseIP("192.168.1.83"),
		Port:     31080,
		Protocol: "tcp",
	})
	rrp.Register(&loadbalancer.Endpoint{
		IP:       net.ParseIP("192.168.1.84"),
		Port:     31080,
		Protocol: "tcp",
	})

	prbr := loadbalancer.NewProber(ctx, rrp)
	prbr.Start()

	// listner, err := net.Listen("tcp", "192.168.1.85:31080")
	// if err != nil {
	// 	log.Panic().Err(err).Msg("failed creating listener")
	// }
	// var wg sync.WaitGroup
	// wg.Add(1)

	// for {
	// 	passiveConn, err := listner.Accept()
	// 	if err != nil {
	// 		log.Panic().Err(err).Msg("failed accepting passive connnection")
	// 	}

	// 	wg.Add(1)
	// 	go func() {
	// 		defer wg.Done()
	// 		activeConn, err := net.Dial("tcp", "192.168.1.82:31080")
	// 		if err != nil {
	// 			log.Panic().Err(err).Msg("failed dialing active connnection")
	// 		}

	// 		fwd := loadbalancer.Forwarder{
	// 			Client: passiveConn,
	// 			Server: activeConn,
	// 		}

	// 		fwd.Do()
	// 	}()
	// }
}
