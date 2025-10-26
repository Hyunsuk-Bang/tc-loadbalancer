package loadbalancer

import (
	"context"
	"encoding/binary"
	"net"
	"structs"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/rs/zerolog/log"
)

func ipv4ToUint32(ip net.IP) uint32 {
	return binary.LittleEndian.Uint32(ip.To4())
}

func ipv6ToUint32(ip net.IP) [4]uint32 {
	var res [4]uint32
	for i := 0; i < 4; i++ {
		res[i] = binary.LittleEndian.Uint32(ip[4*i : 4*(i+1)])
	}
	return res
}

// in progress
func RunTCLB(ctx context.Context, cfg *Config) {
	iface, err := net.InterfaceByName("eno1")
	if err != nil {
		log.Fatal().Msgf("failed to get interface eth0: %v", err)
	}

	// Load pre-compiled programs into the kernel.
	objs := lbObjects{}
	if err := loadLbObjects(&objs, nil); err != nil {
		log.Fatal().Msgf("loading objects: %s", err)
	}
	defer objs.Close()

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.LbTc,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to attach lb_tc")
	}
	defer l.Close()

	//TODO: inject load balancing strategy to ebpf map
	for i, ep := range cfg.Endpoints {
		log.Debug().Str("ep", ep.IP.String()).Msg("inserting ip")
		lbEp := lbEndpoint{
			Ip: struct {
				_  structs.HostLayout
				V6 lbIp6AddrT
			}{
				//V6: ipv6ToUint32(ep.IP.To16()), // V6 with IPv4-mapped address
				V6: lbIp6AddrT{ipv4ToUint32(ep.IP), 0, 0, 0},
			},
			Port:  uint16(ep.Port),
			Alive: 1,
		}

		pool := objs.Pool
		if err := pool.Put(lbEp.Ip, lbEp); err != nil {
			log.Fatal().Err(err).Msg("failed to put map")
		}
		rrp := objs.RoundRobinPool
		if err := rrp.Put(uint32(i), lbEp); err != nil {
			log.Fatal().Err(err).Msg("failed to put map")
		}
	}

	rrpCounterMap := objs.RoundRobinCounter
	var zero uint32 = 0
	if err := rrpCounterMap.Put(uint32(0), zero); err != nil {
		log.Fatal().Err(err).Msg("failed to put round robin counter")
	}

	rrpSizeMap := objs.RoundRobinPoolSize
	size := uint32(len(cfg.Endpoints))
	if err := rrpSizeMap.Put(uint32(0), size); err != nil {
		log.Fatal().Err(err).Msg("failed to put round robin pool size")
	}

	<-ctx.Done()
	log.Info().Msg("shutting down tc load balancer")
}
