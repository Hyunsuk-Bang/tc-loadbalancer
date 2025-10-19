package loadbalancer

import (
	"fmt"
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
	rrp.counter += 1
	idx := rrp.counter % uint64(len(rrp.endpoints))
	ep := rrp.endpoints[idx]

	if epHealth, ok := rrp.endpointHealth[ep]; !ok || !epHealth.health {

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
