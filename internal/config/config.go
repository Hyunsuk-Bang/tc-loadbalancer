package config

import (
	"fmt"
	"io"
	"net"
	"os"

	lb "loadbalancer/internal/loadbalancer"

	"gopkg.in/yaml.v3"
)

// Config represents the top-level configuration derived from example.yaml
// which has a `loadbalancer` mapping containing a `listener` and `endpoints`.
type Config struct {
	Listener  *lb.Endpoint
	Endpoints []*lb.Endpoint
}

type rawListener struct {
	IP       string `yaml:"ip"`
	Port     int    `yaml:"port"`
	Protocol string `yaml:"protocol"`
}

type rawEndpoint struct {
	IP       string `yaml:"ip"`
	Port     int    `yaml:"port"`
	Protocol string `yaml:"protocol"`
}

type rawLoadbalancer struct {
	Listener  rawListener   `yaml:"listener"`
	Endpoints []rawEndpoint `yaml:"endpoints"`
}

type rawConfig struct {
	Loadbalancer rawLoadbalancer `yaml:"loadbalancer"`
}

// Parse decodes YAML from r and returns a Config with validated entries.
func Parse(r io.Reader) (*Config, error) {
	var rc rawConfig
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&rc); err != nil {
		return nil, err
	}

	lbRaw := rc.Loadbalancer
	cfg := &Config{}

	// Validate listener
	if lbRaw.Listener.IP == "" {
		return nil, fmt.Errorf("listener.ip is required")
	}
	lip := net.ParseIP(lbRaw.Listener.IP)
	if lip == nil {
		return nil, fmt.Errorf("listener.ip is invalid: %s", lbRaw.Listener.IP)
	}
	if lbRaw.Listener.Port <= 0 || lbRaw.Listener.Port > 65535 {
		return nil, fmt.Errorf("listener.port is invalid: %d", lbRaw.Listener.Port)
	}
	proto := lbRaw.Listener.Protocol
	if proto == "" {
		proto = "tcp"
	}
	cfg.Listener = &lb.Endpoint{
		IP:       lip,
		Port:     lbRaw.Listener.Port,
		Protocol: proto,
	}

	eps := make([]*lb.Endpoint, 0, len(lbRaw.Endpoints))
	for i, re := range lbRaw.Endpoints {
		if re.IP == "" {
			return nil, fmt.Errorf("endpoints[%d].ip is required", i)
		}
		ip := net.ParseIP(re.IP)
		if ip == nil {
			return nil, fmt.Errorf("endpoints[%d].ip is invalid: %s", i, re.IP)
		}
		if re.Port <= 0 || re.Port > 65535 {
			return nil, fmt.Errorf("endpoints[%d].port is invalid: %d", i, re.Port)
		}
		proto := re.Protocol
		if proto == "" {
			proto = "tcp"
		}
		eps = append(eps, &lb.Endpoint{
			IP:       ip,
			Port:     re.Port,
			Protocol: proto,
		})
	}
	cfg.Endpoints = eps

	return cfg, nil
}

// ParseFile opens path and parses the YAML config file into Config.
func ParseFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}
