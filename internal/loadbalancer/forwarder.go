package loadbalancer

import (
	"io"
	"net"
	"sync"

	"github.com/rs/zerolog/log"
)

type Forwarder struct {
	Client net.Conn
	Server net.Conn
}

// Do starts bidirectional forwarding between Client and Server. It returns once
// both directions have finished and connections are closed. It uses io.Copy to
// efficiently forward data and attempts a graceful shutdown.
func (f *Forwarder) Do() {
	var wg sync.WaitGroup
	log.Debug().Str("client", f.Client.RemoteAddr().String()).Str("server", f.Server.RemoteAddr().String()).Msg("forwarding")

	wg.Add(2)

	copyDirection := func(dst net.Conn, src net.Conn, direction string) {
		defer wg.Done()
		log.Debug().Str("component", "forwarder").Str("direction", direction).Msg("start copy")
		_, err := io.Copy(dst, src)
		if err != nil {
			log.Debug().Str("component", "forwarder").Str("direction", direction).Err(err).Msg("copy finished with error")
		} else {
			log.Debug().Str("component", "forwarder").Str("direction", direction).Msg("copy finished")
		}

		if tcpDst, ok := dst.(*net.TCPConn); ok {
			if err := tcpDst.CloseWrite(); err != nil {
				log.Debug().Str("component", "forwarder").Str("direction", direction).Err(err).Msg("CloseWrite on dst failed")
			} else {
				log.Debug().Str("component", "forwarder").Str("direction", direction).Msg("CloseWrite on dst succeeded")
			}
		} else {
			if dst != nil {
				if err := dst.Close(); err != nil {
					log.Debug().Str("component", "forwarder").Str("direction", direction).Err(err).Msg("Close on non-TCP dst failed")
				}
			}
		}
	}
	go copyDirection(f.Server, f.Client, "client->server")
	go copyDirection(f.Client, f.Server, "server->client")
	wg.Wait()

	if f.Client != nil {
		_ = f.Client.Close()
	}
	if f.Server != nil {
		_ = f.Server.Close()
	}
	log.Info().Str("component", "forwarder").Msg("forwarding finished")
}
