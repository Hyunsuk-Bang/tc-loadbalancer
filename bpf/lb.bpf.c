//go:build ignore
#include "lb.h"

SEC("tc")
int lb_tc(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct tuple tpl = {};

    if (data + sizeof(struct ethhdr) > data_end) return BPF_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return BPF_OK;

    /* L3 */
    ip = data + sizeof(struct ethhdr); 
    if ((void *)(ip + 1) > data_end) return BPF_OK;

    /* L4 (only do tcp) */
    void *transh = (void *)ip + (ip->ihl * 4);
    if (ip->protocol == IPPROTO_TCP) {
        if (transh + sizeof(struct tcphdr) > data_end) return BPF_OK;
        tcp = transh;
    } else {
        return BPF_OK;
    }

    tpl.protocol = ip->protocol;
    tpl.src_ip = ip->saddr;
    tpl.dst_ip = ip->daddr;
    tpl.src_port = tcp->source;
    tpl.dst_port = tcp->dest;

    /* ignore SSH / ignore healthcheck endpoint */
    if (tpl.dst_port == bpf_htons(22) || tpl.src_port == bpf_htons(22))
        return BPF_OK;
    if (tpl.dst_port == bpf_htons(31081) || tpl.src_port == bpf_htons(31081))
        return BPF_OK;


    /* endpoint -> lb, do SNAT */
    struct endpoint *ep = bpf_map_lookup_elem(&endpoints, &tpl.src_ip);
    if (ep && tpl.dst_ip == bpf_htonl(VIP)) {
        struct tuple *mapped = bpf_map_lookup_elem(&session, &tpl); 
        if (!mapped) {
            return BPF_OK;
        }
        __u32 old_saddr = ip->saddr;
        __u32 old_daddr = ip->daddr;
        __u32 new_saddr = mapped->dst_ip;
        __u32 new_daddr = mapped->src_ip;

        struct tuple tpl_rev = {};
        tpl_rev.protocol = mapped->protocol;
        tpl_rev.src_ip = mapped->src_ip;
        tpl_rev.dst_ip = old_saddr;
        tpl_rev.src_port = mapped->src_port;
        tpl_rev.dst_port = mapped->dst_port;

        ip->saddr = new_saddr;
        ip->daddr = new_daddr;
        if (set_tcp_state(tcp, &tpl_rev) < 0) {
            bpf_printk("failed to set tcp state");
            return BPF_DROP;
        }
        if (bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), old_saddr, new_saddr, 4) < 0) return BPF_DROP;
        if (bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), old_daddr, new_daddr, 4) < 0) return BPF_DROP; 
        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check), old_saddr, new_saddr, BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;    
        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check), old_daddr, new_daddr, BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
        return bpf_redirect_neigh(skb->ifindex, NULL, 0, 0);
    }

    /* TODO 
        1. create TCP state machine
        2. If TCP session is not closed, packet should be routed to same endpoint 
    */

    /* lb -> endpoint,  do DNAT */
    __u32 base_ip = bpf_htonl(0xc0a80152);

    struct tuple expected_response = {};
    expected_response.protocol = tpl.protocol;
    expected_response.src_ip = base_ip;  
    expected_response.dst_ip = ip->daddr;
    expected_response.src_port = tpl.dst_port;
    expected_response.dst_port = tpl.src_port;

    bpf_map_update_elem(&session, &expected_response, &tpl, BPF_ANY);
    __u32 old_saddr = ip->saddr;
    __u32 old_daddr = ip->daddr;
    __u32 new_saddr = ip->daddr;
    __u32 new_daddr = base_ip;
    ip->saddr = new_saddr;
    ip->daddr = new_daddr;

    struct tuple mapped = tpl;
    mapped.src_ip = old_saddr;
    mapped.dst_ip = new_daddr;
    if (set_tcp_state(tcp, &mapped) < 0) {
        bpf_printk("failed to set tcp state");
        return BPF_DROP;
    }

    if (bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), old_saddr, new_saddr, 4) < 0) return BPF_DROP;   
    if (bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), old_daddr, new_daddr, 4) < 0) return BPF_DROP;
    if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check), old_saddr, new_saddr, BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
    if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check), old_daddr, new_daddr, BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
    return bpf_redirect_neigh(skb->ifindex,NULL, 0, 0);
}

char LICENSE[] SEC("license") = "GPL";
