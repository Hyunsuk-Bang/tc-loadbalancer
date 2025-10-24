package loadbalancer

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
)

type RandomPool struct {
	endpoints      []*Endpoint
	endpointHealth map[*Endpoint]*EndpointHealth
	mu             sync.Mutex
}

func NewRandomPool() *RandomPool {
	return &RandomPool{
		endpoints:      make([]*Endpoint, 0),
		endpointHealth: make(map[*Endpoint]*EndpointHealth),
		mu:             sync.Mutex{},
	}
}

func (rp *RandomPool) Register(ep *Endpoint) error {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	for _, e := range rp.endpoints {
		if e.IP.Equal(ep.IP) && e.Port == ep.Port && e.Protocol == ep.Protocol {
			return fmt.Errorf("endpoint %s exists", ep.String())
		}
	}

	rp.endpoints = append(rp.endpoints, ep)
	return nil
}

func (rp *RandomPool) Next() *Endpoint {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	var ep *Endpoint
	var eh *EndpointHealth
	for {
		idx := rand.Uint() % uint(len(rp.endpoints))
		ep = rp.endpoints[idx]
		eh = rp.endpointHealth[ep]
		if eh.health {
			break
		}
	}
	return ep
}

func (rp *RandomPool) List() []*Endpoint {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	return rp.endpoints
}

func (rp *RandomPool) SetEndpointHealth(ep *Endpoint, health bool) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if eh, ok := rp.endpointHealth[ep]; !ok {
		rp.endpointHealth[ep] = &EndpointHealth{health: health}
	} else {
		eh.health = health
	}
}

func (rpp *RandomPool) String() string {
	rpp.mu.Lock()
	defer rpp.mu.Unlock()
	var sb strings.Builder
	for ep, health := range rpp.endpointHealth {
		sb.WriteString(fmt.Sprintf("%s: %v\n", ep.String(), health.health))
	}
	return sb.String()
}
