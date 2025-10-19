package loadbalancer

import (
	"context"
	"fmt"
	"net"

	"github.com/rs/zerolog/log"
)

type Loadbalancer struct {
	listenter net.Listener
	context   context.Context
	memory    map[string]net.Conn
}

func New(ctx context.Context, ip net.IP, port int, protocol string) (Loadbalancer, error) {
	lb := Loadbalancer{}
	if protocol != "tcp" && protocol != "udp" {
		return lb, fmt.Errorf("unsupported protocol: %s", protocol)
	}

	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	listener, err := net.Listen(protocol, addr)
	if err != nil {
		return lb, err
	}

	lb.listenter = listener
	lb.context = ctx
	lb.memory = make(map[string]net.Conn)
	return lb, nil
}

func (l *Loadbalancer) Start() error {
	for {
		conn, err := l.listenter.Accept()
		if err != nil {
			log.Error().Err(err).Str("component", "listener").Msg("failed accept")
			continue
		}
		fmt.Println("localaddr: ", conn.LocalAddr().String())
		fmt.Println("remoteaddr: ", conn.RemoteAddr().String())
		conn.Close()

		//conn, exists := l.memory[conn.RemoteAddr().String()]
	}
}
