#ifndef LB_H
#define LB_H
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define IPFAMILY_IPV4 4
#define IPFAMILY_IPV6 6

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

typedef unsigned int ip4_addr_t;
typedef unsigned int ip6_addr_t[4];

/*
Order of members in union ip_addr is important when bpg2go generates go struct
putting ipv4 first yields the following go struct:
type lbEndpoint struct {
    _  structs.HostLayout
    Ip struct {
        _  structs.HostLayout
        V4 lbIp4AddrT
        _  [12]byte
    }
    Port    uint16
    Alive   uint8
    Ifindex uint8
}
this would make it harder to access ipv6 address since we cannot access _ [12]byte directly.

By putting ipv6 first, bpf2go generates:
type lbEndpoint struct {
    _  structs.HostLayout
    Ip struct {
        _  structs.HostLayout
        V6 lbIp6AddrT
    }
    Port    uint16
    Alive   uint8
    Ifindex uint8
}
which makes it easier to access both ipv4 and ipv6 address.
*/
union ip_addr {
    ip6_addr_t v6; // IPv6 address (16 bytes)
    ip4_addr_t v4;  // IPv4 address (4 bytes)
} ip_addr_t;

struct endpoint {
    union ip_addr ip;
    __u16 port;
    __u8 alive;
    __u8 ifindex;
};

struct tuple {
    __u8 protocol;
    union ip_addr src_ip;
    union ip_addr dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, union ip_addr); // key is ip address of endpoint
    __type(value, struct endpoint);
} pool SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct tuple);
    __type(value, struct tuple);
} connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} round_robin_counter SEC(".maps");

// will be written by user-space program at initialization
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} round_robin_pool_size SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32); // key is index in the roud robin pool
    __type(value, struct endpoint);
} round_robin_pool SEC(".maps");

// Revalidate skb data pointers
static __always_inline int revalidate_data(
    struct __sk_buff *skb,
    void **data,
    void **data_end,
    void **hdr,
    __u32 offset,
    __u32 size
){
    if (bpf_skb_pull_data(skb, skb->len) < 0)
        return -1;

    *data = (void *)(long)skb->data;
    *data_end = (void *)(long)skb->data_end;
    *hdr = *data + offset;
    if (*hdr + size + 1 > *data_end) return -1;
    return 0;
}

// Compare two ip_addr unions based on protocol
// return 0 if equal, non-zero otherwise
static __always_inline int addr_cmp(union ip_addr *a, union ip_addr *b, __u8 ip_family) {
    if (ip_family == IPFAMILY_IPV4 && a->v4 == b->v4) {
        return 0;
    } else if (ip_family == IPFAMILY_IPV6) {
        return __builtin_memcmp(a->v6, b->v6, sizeof(a->v6));
    }
    return -1;
}

#endif  // LB_H