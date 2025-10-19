package loadbalancer

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	probeInterval = 5 * time.Second
)

type ProbeConn struct {
	conn net.Conn
}

type Prober struct {
	pool    Pool
	conns   map[*Endpoint]*ProbeConn
	mu      sync.Mutex
	context context.Context
}

func NewProber(ctx context.Context, pool Pool) Prober {
	return Prober{
		pool:    pool,
		mu:      sync.Mutex{},
		conns:   make(map[*Endpoint]*ProbeConn),
		context: ctx,
	}
}

func (prbr *Prober) Start() {
	var conn net.Conn
	var err error

	endpoints := prbr.pool.List()
	for _, ep := range endpoints {
		if _, ok := prbr.conns[ep]; !ok {
			prbConn := &ProbeConn{}
			switch ep.Protocol {
			case "tcp":
				conn, err = net.DialTCP("tcp", nil, &net.TCPAddr{
					IP:   ep.IP,
					Port: ep.Port,
				})
				prbConn.conn = conn
				log.Debug().Str("component", "prober").Str("protocol", ep.Protocol).Str("endpoint", ep.String()).Msg("probe registered")
				prbr.conns[ep] = prbConn
			case "udp":
				conn, err = net.DialUDP("udp", nil, &net.UDPAddr{
					IP:   ep.IP,
					Port: ep.Port,
				})
				prbConn.conn = conn
				log.Debug().Str("component", "prober").Str("protocol", ep.Protocol).Str("endpoint", ep.String()).Msg("probe registered")
				prbr.conns[ep] = prbConn
			default:
				prbConn = nil
				log.Warn().Str("component", "prober").Str("protocol", ep.Protocol).Str("endpoint", ep.String()).Msg("unsupported protocol; registering probe without connection")
			}
			if err != nil {
				continue
			}
		}
	}

	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-prbr.context.Done():
			log.Info().Str("component", "prober").Msg("Exiting")
			return
		case <-ticker.C:
			for ep, pconn := range prbr.conns {
				if pconn.conn == nil {
					prbr.pool.SetEndpointHealth(ep, false)
				}
				_, err := pconn.conn.Write([]byte("HI"))
				if err != nil {
					log.Error().Str("component", "prober").Err(err).Msg("probe write failed")
					continue
				}
				log.Debug().Str("component", "prober").Err(err).Str("endpoint", ep.String()).Msg("probed")
				prbr.pool.SetEndpointHealth(ep, true)
			}
		}
	}
}
