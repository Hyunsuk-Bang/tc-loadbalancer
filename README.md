# tc-loadbalancer
A Linux eBPF-based load balancer prototype. This project is currently under development and not yet complete.

## Project Structure
- `main.go`: Main Go application entry point
- `loadbalancer.bpf.c`: eBPF program source code
- `lb.h`: Shared header for eBPF and Go
- `bpf_bpfeb.go`, `bpf_bpfel.go`: Auto-generated Go bindings for eBPF
- `makefile`: Build instructions
- `go.mod`, `go.sum`: Go module files


## Next Steps / TODO
- [ ] Logic for select backend
- [ ] Add TCP session to ensure TCP connection are forwarded to same backend
- [ ] Add IPv6 support
- [ ] Add support for encapsulation (VXLAN, VLAN)

## Progress
- [ ] SNAT / DNAT
- [ ] Checksum calculation

## Requirements
- Linux with eBPF support
- Go (>=1.18 recommended)
- clang/llvm for eBPF compilation

## License
TBD

---
*This README will be updated as development progresses.*