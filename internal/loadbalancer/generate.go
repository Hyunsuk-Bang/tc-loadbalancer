package loadbalancer

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -type ip4_addr_t -type ip6_addr_t -verbose -tags linux lb ../../bpf/lb.bpf.c
