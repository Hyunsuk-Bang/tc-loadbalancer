# tc-loadbalancer
A Linux eBPF-based load balancer prototype. This project is currently under development and not yet complete.

 Currently the load balancer creates two sockets per client (client→LB and LB→backend) and forwards data with Go’s io.Copy. That works in most cases, but it wastes file descriptors and CPU for memory copies. By using eBPF to redirect packets in-kernel we can avoid the extra socket pair and user-space copying, reducing latency and resource usage.

<img width="541" height="518" alt="Untitled Diagram drawio" src="https://github.com/user-attachments/assets/db44c56d-3f66-4502-8f3b-064f272fdc5d" />

## Project Structure
- `main.go`: Main Go application entry point
- `loadbalancer.bpf.c`: eBPF program source code
- `lb.h`: Shared header for eBPF and Go
- `makefile`: Build instructions
- `go.mod`, `go.sum`: Go module files

## DONE
- [x] userspace level loadbalancer
- [x] SNAT / DNAT
- [x] Checksum calculation
- [X] Userspace LB with Round Robin and Rabdom Pool
- [X] Change bpf code to support IPv4 and IPv6

## In Progress
- [ ] TCP state tracker

## Next Steps / TODO
- [ ] Logic for backend selection (rr, Least connection and etc)
- [ ] Ensures that all packets belonging to the same TCP connection are consistently forwarded to the same backend server
- [ ] support for encapsulation (VXLAN, VLAN)
- [ ] Add weighing functionality, which could be useful for canary deployment and replacing backend node for HW failure

## Future
- [] Implement more sophisticated load balancing algorithm (Load aware, maglev hashing, and etc)

## DEMO (POC)
![Screen Recording 2025-10-12 at 7 40 04 PM](https://github.com/user-attachments/assets/f92526d6-423c-495b-acc7-47dbdbd69446)

## Performance
#### Direct connection between two hosts (MTU 1500)
```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  24.9 GBytes  21.4 Gbits/sec  3267             sender
[  5]   0.00-10.00  sec  24.9 GBytes  21.4 Gbits/sec                  receiver
```

#### with tc-LB (MTU 1500)
```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  20.5 GBytes  17.6 Gbits/sec  655             sender
[  5]   0.00-10.00  sec  20.5 GBytes  17.6 Gbits/sec                  receiver
```

#### Userspace LB using io.Copy (MTU 1500)
```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  14.4 GBytes  12.4 Gbits/sec  945             sender
[  5]   0.00-10.00  sec  14.4 GBytes  12.4 Gbits/sec                  receiver
```


#### Direct connection between two hosts (MTU 9000)
```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  42.5 GBytes  36.5 Gbits/sec    0             sender
[  5]   0.00-10.00  sec  42.5 GBytes  36.5 Gbits/sec                  receiver
```

#### with tc-LB (MTU 9000)
```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  28.8 GBytes  24.7 Gbits/sec    1             sender
[  5]   0.00-10.00  sec  28.8 GBytes  24.7 Gbits/sec                  receiver
```

#### Userspace LB using io.Copy (MTU 9000)
```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  21.6 GBytes  18.5 Gbits/sec    7             sender
[  5]   0.00-10.00  sec  21.5 GBytes  18.5 Gbits/sec                  receiver
```


## Requirements
- Linux with eBPF support
- Go

## License
TBD

---
*This README will be updated as development progresses.*
