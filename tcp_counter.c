// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <xdp/parsing_helpers.h>

/* Define a BPF map to store packet counts per IP address */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);  // IPv4 address
    __type(value, __u64); // Packet count
} tcp_counter_map SEC(".maps");

SEC("xdp")
int tcp_counter_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh;
    struct ethhdr *eth;
    int eth_type, ip_type;
    struct iphdr *iphdr;
    struct tcphdr *tcphdr;
    __u32 src_ip;
    __u64 *pkt_count;
    __u64 one = 1;

    /* Initialize header cursor */
    nh.pos = data;

    /* Parse Ethernet header */
    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0)
        return XDP_PASS;

    /* Parse IP header */
    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
        if (ip_type < 0)
            return XDP_PASS;

        /* Check if it's a TCP packet */
        if (ip_type == IPPROTO_TCP) {
            /* Parse TCP header */
            if (parse_tcphdr(&nh, data_end, &tcphdr) < 0)
                return XDP_PASS;

            /* Get source IP address */
            src_ip = iphdr->saddr;

            /* Update packet count for this IP address */
            pkt_count = bpf_map_lookup_elem(&tcp_counter_map, &src_ip);
            if (pkt_count) {
                /* Increment existing counter */
                (*pkt_count)++;
            } else {
                /* Insert new counter with initial value 1 */
                bpf_map_update_elem(&tcp_counter_map, &src_ip, &one, BPF_ANY);
            }
        }
    }

    /* Allow the packet to pass through */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL"; 