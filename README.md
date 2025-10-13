# tc-loadbalancer
A Linux eBPF-based load balancer prototype. This project is currently under development and not yet complete.


<img width="541" height="518" alt="Untitled Diagram drawio" src="https://github.com/user-attachments/assets/db44c56d-3f66-4502-8f3b-064f272fdc5d" />

## Project Structure
- `main.go`: Main Go application entry point
- `loadbalancer.bpf.c`: eBPF program source code
- `lb.h`: Shared header for eBPF and Go
- `makefile`: Build instructions
- `go.mod`, `go.sum`: Go module files

## DONE
- [x] SNAT / DNAT
- [x] Checksum calculation

## In Progress
- [ ] TCP state tracker

## Next Steps / TODO
- [ ] Logic for select backend
- [ ] Ensures that all packets belonging to the same TCP connection are consistently forwarded to the same backend server
- [ ] IPv6 support
- [ ] support for encapsulation (VXLAN, VLAN)

## DEMO (POC)
![Screen Recording 2025-10-12 at 7 40 04 PM](https://github.com/user-attachments/assets/f92526d6-423c-495b-acc7-47dbdbd69446)



## Requirements
- Linux with eBPF support
- Go

## License
TBD

---
*This README will be updated as development progresses.*
