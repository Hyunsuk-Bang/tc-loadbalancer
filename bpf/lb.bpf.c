//go:build ignore
#include "lb.h" 

SEC("tc")
int lb_tc(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct ipv6hdr *ip6;
    struct tcphdr *tcp;
    struct tuple tpl = {};

    __u8 ip_family;
    if (data + sizeof(struct ethhdr) > data_end) return BPF_OK;
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        ip_family = IPFAMILY_IPV4;
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        ip_family = IPFAMILY_IPV6;
    } else {
        return BPF_OK;
    }

    __u32 trans_offset = sizeof(struct ethhdr);
    if (ip_family == IPFAMILY_IPV4) {
        ip = data + sizeof(struct ethhdr);
        if (revalidate_data(skb, &data, &data_end, (void **)&ip, sizeof(struct ethhdr), sizeof(struct iphdr)) < 0) return BPF_DROP;
        tpl.protocol = ip->protocol;
        tpl.src_ip.v4 = ip->saddr;
        tpl.dst_ip.v4 = ip->daddr;
        trans_offset += ip->ihl * 4;
    } else if (ip_family == IPFAMILY_IPV6) {
        ip6 = data + sizeof(struct ethhdr);
        if (revalidate_data(skb, &data, &data_end, (void **)&ip6, sizeof(struct ethhdr), sizeof(struct ipv6hdr)) < 0) return BPF_DROP;
        tpl.protocol = ip6->nexthdr;
        __builtin_memcpy(tpl.src_ip.v6, ip6->saddr.s6_addr32, sizeof(ip6->saddr.s6_addr32));
        __builtin_memcpy(tpl.dst_ip.v6, ip6->daddr.s6_addr32, sizeof(ip6->daddr.s6_addr32));
        /* TODO: ipv6 may contain multiple chain of headers. For now, we'll consider size of the ipv6 header as 40*/
        trans_offset += sizeof(struct ipv6hdr);
    }

    if (tpl.protocol == IPPROTO_TCP) {
        tcp = data + trans_offset;
        if (revalidate_data(skb, &data, &data_end, (void **)&tcp, trans_offset, sizeof(struct tcphdr)) < 0) return BPF_DROP;
        tpl.src_port = tcp->source;
        tpl.dst_port = tcp->dest;
    } else {
        /* TODO: handle UDP */
        return BPF_OK;
    }

    /* ignore SSH */
    if (tpl.dst_port == bpf_htons(22) || tpl.src_port == bpf_htons(22)) return BPF_OK;

    /*
    src_ip is VIP
    */
    struct endpoint *ep = bpf_map_lookup_elem(&pool, &tpl.src_ip);
    struct tuple *mapped = bpf_map_lookup_elem(&connections, &tpl);
    union ip_addr old_saddr;
    union ip_addr old_daddr;
    union ip_addr new_saddr;
    union ip_addr new_daddr;
    if (ep && mapped && ip_family == IPFAMILY_IPV4) {
        ip = data + sizeof(struct ethhdr);
        if (revalidate_data(skb, &data, &data_end, (void **)&ip, sizeof(struct ethhdr), sizeof(struct iphdr)) < 0) return BPF_DROP;
        old_saddr = tpl.src_ip;
        old_daddr = tpl.dst_ip;
        new_saddr = mapped->dst_ip;
        new_daddr = mapped->src_ip;

        ip->saddr = new_saddr.v4;
        ip->daddr = new_daddr.v4;
        if (bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), old_saddr.v4, new_saddr.v4, 4) < 0) return BPF_DROP;
        if (bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), old_daddr.v4, new_daddr.v4, 4) < 0) return BPF_DROP;
        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check), old_saddr.v4, new_saddr.v4, BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check), old_daddr.v4, new_daddr.v4, BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
        return bpf_redirect_neigh(skb->ifindex, NULL, 0, 0);
    } else if (ep && mapped && ip_family == IPFAMILY_IPV6) {
        ip6 = data + sizeof(struct ethhdr);
        if (revalidate_data(skb, &data, &data_end, (void **)&ip6, sizeof(struct ethhdr), sizeof(struct ipv6hdr)) < 0) return BPF_DROP;
        old_saddr = tpl.src_ip;
        old_daddr = tpl.dst_ip;
        new_saddr = mapped->dst_ip;
        new_daddr = mapped->src_ip;
        __builtin_memcpy(ip6->saddr.s6_addr32, new_saddr.v6, sizeof(ip6->saddr.s6_addr32));
        __builtin_memcpy(ip6->daddr.s6_addr32, new_daddr.v6, sizeof(ip6->daddr.s6_addr32));

        /* IPv6 delete checksum operation to transport layer */
        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check), old_saddr.v6[0], new_saddr.v6[0], BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check), old_saddr.v6[1], new_saddr.v6[1], BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check), old_saddr.v6[2], new_saddr.v6[2], BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check), old_saddr.v6[3], new_saddr.v6[3], BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;

        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check), old_daddr.v6[0], new_daddr.v6[0], BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check), old_daddr.v6[1], new_daddr.v6[1], BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check), old_daddr.v6[2], new_daddr.v6[2], BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check), old_daddr.v6[3], new_daddr.v6[3], BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
        return bpf_redirect_neigh(skb->ifindex, NULL, 0, 0);
    }
    // packet is from one of the pool endpoints to LB, However, no mapping found.
    if (ep) return BPF_OK;

    __u32 *rr_counter;
    __u32 *rr_pool_size;
    __u32 rr_counter_key = 0;
    __u32 rr_pool_size_key = 0;
    rr_counter = bpf_map_lookup_elem(&round_robin_counter, &rr_counter_key);
    rr_pool_size = bpf_map_lookup_elem(&round_robin_pool_size, &rr_pool_size_key);
    if (!rr_counter) {
        return BPF_DROP;
    }

    if (!rr_pool_size || *rr_pool_size == 0) {
        return BPF_DROP;
    }
    __u32 index = *rr_counter % *rr_pool_size;
    struct endpoint *selected_ep = bpf_map_lookup_elem(&round_robin_pool, &index);
    if (!selected_ep || !selected_ep->alive) {
        return BPF_DROP;
    }

    __u32 new_rr_counter = *rr_counter + 1;
    if (bpf_map_update_elem(&round_robin_counter, &rr_counter_key, &new_rr_counter, BPF_ANY) < 0) {
        bpf_printk("Failed to update rr counter\n");
        return BPF_DROP;
    }

    // Store expected resonse from one of the pool
    struct tuple expected_response = {};
    if (ip_family == IPFAMILY_IPV4) {
        ip = data + sizeof(struct ethhdr);
        if (revalidate_data(skb, &data, &data_end, (void **)&ip, sizeof(struct ethhdr), sizeof(struct iphdr)) < 0) return BPF_DROP;
        expected_response.protocol = tpl.protocol;
        expected_response.src_ip.v4 = selected_ep->ip.v4;
        expected_response.dst_ip.v4 = tpl.dst_ip.v4;
        expected_response.src_port = tpl.dst_port;
        expected_response.dst_port = tpl.src_port;

        old_saddr.v4 = ip->saddr;
        old_daddr.v4 = ip->daddr;
        new_saddr.v4 = ip->daddr;
        new_daddr.v4 = selected_ep->ip.v4;

        ip->saddr = new_saddr.v4;
        ip->daddr = new_daddr.v4;
        if (bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), old_saddr.v4, new_saddr.v4, 4) < 0) return BPF_DROP;
        if (bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), old_daddr.v4, new_daddr.v4, 4) < 0) return BPF_DROP;
        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check), old_saddr.v4, new_saddr.v4, BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check), old_daddr.v4, new_daddr.v4, BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
        bpf_map_update_elem(&connections, &expected_response, &tpl, BPF_ANY);
        return bpf_redirect_neigh(skb->ifindex,NULL, 0, 0);
    } else if (ip_family == IPFAMILY_IPV6) {
        ip6 = data + sizeof(struct ethhdr);
        if (revalidate_data(skb, &data, &data_end, (void **)&ip6, sizeof(struct ethhdr), sizeof(struct ipv6hdr)) < 0) return BPF_DROP;
        expected_response.protocol = tpl.protocol;
        __builtin_memcpy(expected_response.src_ip.v6, selected_ep->ip.v6, sizeof(ip6->saddr.s6_addr32));
        __builtin_memcpy(expected_response.dst_ip.v6, ip6->daddr.s6_addr32, sizeof(ip6->daddr.s6_addr32));
        expected_response.src_port = tpl.dst_port;
        expected_response.dst_port = tpl.src_port;
        __builtin_memcpy(old_saddr.v6, ip6->saddr.s6_addr32, sizeof(ip6->saddr.s6_addr32));
        __builtin_memcpy(old_daddr.v6, ip6->daddr.s6_addr32, sizeof(ip6->daddr.s6_addr32));
        __builtin_memcpy(new_saddr.v6, ip6->daddr.s6_addr32, sizeof(ip6->daddr.s6_addr32));
        __builtin_memcpy(new_daddr.v6, selected_ep->ip.v6, sizeof(ip6->saddr.s6_addr32));

        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check), old_saddr.v6[0], new_saddr.v6[0], BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check), old_saddr.v6[1], new_saddr.v6[1], BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check), old_saddr.v6[2], new_saddr.v6[2], BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check), old_saddr.v6[3], new_saddr.v6[3], BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;

        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check), old_daddr.v6[0], new_daddr.v6[0], BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check), old_daddr.v6[1], new_daddr.v6[1], BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check), old_daddr.v6[2], new_daddr.v6[2], BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check), old_daddr.v6[3], new_daddr.v6[3], BPF_F_PSEUDO_HDR | 4) < 0) return BPF_DROP;
        bpf_map_update_elem(&connections, &expected_response, &tpl, BPF_ANY);
        return bpf_redirect_neigh(skb->ifindex,NULL, 0, 0);
    }
    return BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";
