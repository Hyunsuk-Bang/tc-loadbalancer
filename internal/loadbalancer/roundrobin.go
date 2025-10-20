package loadbalancer

import (
	"fmt"
	"strings"
	"sync"
)

type RoundRobinPool struct {
	endpoints      []*Endpoint
	endpointHealth map[*Endpoint]*EndpointHealth
	counter        uint64
	mu             sync.Mutex
}

func NewRoundRobinPool() *RoundRobinPool {
	return &RoundRobinPool{
		endpoints:      make([]*Endpoint, 0),
		counter:        0,
		endpointHealth: make(map[*Endpoint]*EndpointHealth),
		mu:             sync.Mutex{},
	}
}

func (rrp *RoundRobinPool) Register(ep *Endpoint) error {
	rrp.mu.Lock()
	defer rrp.mu.Unlock()
	for _, e := range rrp.endpoints {
		if e.IP.Equal(ep.IP) && e.Port == ep.Port && e.Protocol == ep.Protocol {
			return fmt.Errorf("endpoint %s exists", ep.String())
		}
	}

	rrp.endpoints = append(rrp.endpoints, ep)
	return nil
}

func (rrp *RoundRobinPool) Next() *Endpoint {
	rrp.mu.Lock()
	defer rrp.mu.Unlock()
	var ep *Endpoint
	var eh *EndpointHealth
	for {
		idx := rrp.counter % uint64(len(rrp.endpoints))
		ep = rrp.endpoints[idx]
		eh = rrp.endpointHealth[ep]
		rrp.counter++
		if eh.health {
			break
		}
	}
	return ep
}

func (rrp *RoundRobinPool) List() []*Endpoint {
	rrp.mu.Lock()
	defer rrp.mu.Unlock()
	return rrp.endpoints
}

func (rrp *RoundRobinPool) SetEndpointHealth(ep *Endpoint, health bool) {
	rrp.mu.Lock()
	defer rrp.mu.Unlock()
	if eh, ok := rrp.endpointHealth[ep]; !ok {
		rrp.endpointHealth[ep] = &EndpointHealth{health: health}
	} else {
		eh.health = health
	}
}

func (rpp *RoundRobinPool) String() string {
	rpp.mu.Lock()
	defer rpp.mu.Unlock()
	var sb strings.Builder
	for ep, health := range rpp.endpointHealth {
		sb.WriteString(fmt.Sprintf("%s: %v\n", ep.String(), health.health))
	}
	return sb.String()
}
