#ifndef LB_H
#define LB_H
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define VIP 0xc0a80155
#define MAX_TCP_CHECK_WORDS 750 // 32 * 2 = 64 bytes max TCP header + payload to csum
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define TCP_CLOSED 0
#define TCP_SYN_SENT 1
#define TCP_ESTABLISHED 2
#define TCP_HALF_CLOSED 3 

struct endpoint {
    __u32 ip;
    __u16 port;
    __u8  alive;
    __u8  ifindex;
};

struct tuple {
    __u8 protocol;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct tcp_state {
    __u8 tcp_state;
    __u64 start_time;
    __u64 last_ack_time;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32); // key is ip address of endpoint
    __type(value, struct endpoint);
} endpoints SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct tuple); // simplified session key
    __type(value, struct tuple); // mapped endpoint
} session SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct tuple); 
    __type(value, __u64);
} session_timestamp SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct tuple);
    __type(value, struct tcp_state);
} tcp_state_map SEC(".maps");
 
// Revalidate skb data pointers
static __always_inline int revalidate_data(struct __sk_buff *skb,
                                           void **data,
                                           void **data_end,
                                           void **hdr,
                                           __u32 offset,
                                           __u32 size
                                        ) {
    if (bpf_skb_pull_data(skb, skb->len) < 0)
        return -1;

    *data = (void *)(long)skb->data;
    *data_end = (void *)(long)skb->data_end;
    *hdr = *data + offset;
    if (*hdr + size + 1 > *data_end) return -1;
    return 0;
}

static __always_inline int set_tcp_state(struct tcphdr *tcphdr, struct tuple *tpl) {
    __u64 tstmp = bpf_ktime_get_ns();

    struct tcp_state *ts = (struct tcp_state*)bpf_map_lookup_elem(&tcp_state_map, tpl);
    if (!ts) {
        struct tcp_state new_ts = {};
        new_ts.tcp_state = TCP_CLOSED;
        new_ts.start_time = tstmp;
        new_ts.last_ack_time = 0;
        if (bpf_map_update_elem(&tcp_state_map, tpl, &new_ts, BPF_ANY) < 0) {
            bpf_printk("Failed to insert new tcp_state");
            return -1;
        }
    }

    ts = bpf_map_lookup_elem(&tcp_state_map, tpl);
    if (!ts) { // still need to check this to avoid verifier issues
        bpf_printk("Failed to lookup tcp_state after insert");
        return -1;
    }

    else if (tcphdr->fin) {
        ts->tcp_state = TCP_HALF_CLOSED;
        return bpf_map_update_elem(&tcp_state_map, tpl, ts, BPF_ANY);
    }

    // Active open
    if (tcphdr->syn && !tcphdr->ack) {
        ts->tcp_state = TCP_SYN_SENT; 
    }

    // Established SYN->, <-SYN,ACK
    else if (tcphdr->syn && tcphdr->ack) {
        ts->tcp_state = TCP_ESTABLISHED; 
    }

    // Normal ACK packet without SYN
    else if (tcphdr->ack && !tcphdr->syn && !tcphdr->fin) { 
        ts->last_ack_time = tstmp;
        ts->tcp_state = TCP_ESTABLISHED;
    }
    return bpf_map_update_elem(&tcp_state_map, tpl, ts, BPF_ANY);
}
#endif  // LB_H