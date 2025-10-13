# tc-loadbalancer
A Linux eBPF-based load balancer prototype. This project is currently under development and not yet complete.
<img width="541" height="518" alt="Untitled Diagram drawio" src="https://github.com/user-attachments/assets/db44c56d-3f66-4502-8f3b-064f272fdc5d" />

## Project Structure
- `main.go`: Main Go application entry point
- `loadbalancer.bpf.c`: eBPF program source code
- `lb.h`: Shared header for eBPF and Go
- `makefile`: Build instructions
- `go.mod`, `go.sum`: Go module files

## Progress
- [x] SNAT / DNAT
- [x] Checksum calculation

## Next Steps / TODO
- [ ] Logic for select backend
- [ ] Add TCP session to ensure TCP connection are forwarded to same backend
- [ ] Add IPv6 support
- [ ] Add support for encapsulation (VXLAN, VLAN)

## Requirements
- Linux with eBPF support
- Go

## License
TBD

---
*This README will be updated as development progresses.*
