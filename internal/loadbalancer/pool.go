package loadbalancer

import (
	"fmt"
	"net"
)

type Endpoint struct {
	IP       net.IP
	Port     int
	Protocol string
}

type EndpointHealth struct {
	health bool
}

type Pool interface {
	Register(*Endpoint) error
	Next() *Endpoint
	List() []*Endpoint
	SetEndpointHealth(ep *Endpoint, health bool)
}

func (e Endpoint) String() string {
	return fmt.Sprintf("%s:%d", e.IP.String(), e.Port)
}
