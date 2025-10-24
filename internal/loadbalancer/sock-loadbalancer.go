package loadbalancer

import (
	"context"
	"net"
	"sync"

	"github.com/rs/zerolog/log"
)

func RunSocketLB(ctx context.Context, cfg *Config) {
	var pool Pool
	switch cfg.Kind {
	case loadBalancerKindRandom:
		pool = NewRandomPool()
	case loadBalancerKindRoundRobin:
		pool = NewRoundRobinPool()
	default:
		log.Warn().Msg("invalid loadbalancing strategy. Using round-robin")
	}

	for _, ep := range cfg.Endpoints {
		pool.Register(ep)
	}
	prbr := NewProber(ctx, pool)
	go prbr.Start()

	listner, err := net.Listen(cfg.Listener.Protocol, cfg.Listener.String())
	if err != nil {
		log.Panic().Err(err).Msg("failed creating listener")
	}
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
				ep := pool.Next()
				activeConn, err := net.Dial(ep.Protocol, ep.String())
				if err != nil {
					log.Error().Err(err).Msg("failed dialing active connection")
					pc.Close()
					return
				}

				fwd := SockForwarder{
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
	listner.Close()
	log.Info().Msg("shutdown complete")
}
