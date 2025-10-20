// main.go
package main

import (
	"context"
	"flag"
	"loadbalancer/internal/config"
	"loadbalancer/internal/loadbalancer"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux lb bpf/lb.bpf.c

func main() {
	debug := flag.Bool("debug", false, "sets log level to debug")
	flag.Parse()
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		cancel()
	}()

	rrp := loadbalancer.NewRoundRobinPool()
	cfg, err := config.ParseFile("example/example.yaml")
	if err != nil {
		log.Panic().Err(err).Msg("failed parsing yaml")
	}
	for _, ep := range cfg.Endpoints {
		rrp.Register(ep)
	}
	prbr := loadbalancer.NewProber(ctx, rrp)
	go prbr.Start()

	listner, err := net.Listen(cfg.Listener.Protocol, cfg.Listener.String())
	if err != nil {
		log.Panic().Err(err).Msg("failed creating listener")
	}

	go func() {
		<-ctx.Done()
		log.Info().Msg("shutting down listener")
		listner.Close()
	}()

	var wg sync.WaitGroup
	acceptLoop := func() {
		for {
			passiveConn, err := listner.Accept()
			if err != nil {
				log.Error().Err(err)
				return
			}
			wg.Add(1)
			go func(pc net.Conn) {
				defer wg.Done()
				ep := rrp.Next()
				activeConn, err := net.Dial(ep.Protocol, ep.String())
				if err != nil {
					log.Error().Err(err).Msg("failed dialing active connection")
					pc.Close()
					return
				}

				fwd := loadbalancer.Forwarder{
					Client: pc,
					Server: activeConn,
				}
				fwd.Do()
			}(passiveConn)
		}
	}

	go acceptLoop()

	// Wait for cancellation and for in-flight handlers to finish.
	<-ctx.Done()
	log.Info().Msg("shutdown requested; waiting for handlers to finish")
	wg.Wait()
	log.Info().Msg("shutdown complete")
}
