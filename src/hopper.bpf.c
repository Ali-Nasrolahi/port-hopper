/* clang-format off */
#include <linux/bpf.h>
/* clang-format on */
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/if.h>

#include "common.h"

#define VERBOSE

#ifdef VERBOSE
#define print(tag, fmt, ...)                                                                       \
    bpf_printk("%s: Index %u, Name %s, IP: src %pI4, dest %pI4, Port: src %u, dest %u\t" fmt, tag, \
               ctx->ingress_ifindex, ifname, &ip->saddr, &ip->daddr, bpf_ntohs(tcp->source),       \
               bpf_ntohs(tcp->dest), ##__VA_ARGS__)
#else
#define print(tag, fmt, ...) ;
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, struct hopper_opt);
    __uint(max_entries, 1);
} config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, char[IF_NAMESIZE]);
    __uint(max_entries, 10);
} if2name SEC(".maps");

static __always_inline int verify_n_parse(struct hopper_opt* opt, void* data, void* data_end,
                                          struct ethhdr** eth, struct iphdr** ip,
                                          struct tcphdr** tcp)
{
    *eth = data;
    *ip = (void*)(*eth + 1);
    *tcp = (void*)(*ip + 1);

    if (!opt || opt->max_p <= opt->min_p || (void*)(*tcp + 1) > data_end ||
        bpf_ntohs((*eth)->h_proto) != ETH_P_IP || (*ip)->protocol != IPPROTO_TCP ||
        (void*)(*tcp) + 60 > data_end) {
        return -1;
    }

    return 0;
}

SEC("tc")
int tc_port_hopper_egress(struct __sk_buff* ctx)
{
    int key = 0;
    struct ethhdr* eth;
    struct iphdr* ip;
    struct tcphdr* tcp;
    struct hopper_opt* opt;
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    opt = bpf_map_lookup_elem(&config, &key);
    key = ctx->ingress_ifindex;
    const char* ifname = bpf_map_lookup_elem(&if2name, &key) ?: "[na]";

    if (verify_n_parse(opt, data, data_end, &eth, &ip, &tcp) ||
        !(tcp->dest == bpf_htons(opt->in_p) || tcp->source == bpf_htons(opt->in_p)))
        goto out;

    __be16* o_p = tcp->dest == bpf_htons(opt->in_p) ? &tcp->dest : &tcp->source;
    __be16 n_p = bpf_htons((bpf_get_prandom_u32() % (opt->max_p - opt->min_p)) + opt->min_p);

    print("EG", "(%u ==> %u)", bpf_ntohs(*o_p), bpf_ntohs(n_p));
    *o_p = n_p;
    bpf_csum_diff(0, 0, (void*)tcp, tcp->doff * 4, 0);

out:
    return TC_ACT_OK;
}

static __always_inline int in_range(struct hopper_opt* opt, __be16 port)
{
    port = bpf_ntohs(port);
    return port < opt->max_p && port >= opt->min_p;
}

SEC("xdp")
int xdp_port_hopper_ingress(struct xdp_md* ctx)
{
    int key = 0;
    struct ethhdr* eth;
    struct iphdr* ip;
    struct tcphdr* tcp;
    struct hopper_opt* opt;
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    opt = bpf_map_lookup_elem(&config, &key);
    key = ctx->ingress_ifindex;
    const char* ifname = bpf_map_lookup_elem(&if2name, &key) ?: "[na]";

    if (verify_n_parse(opt, data, data_end, &eth, &ip, &tcp) ||
        !(in_range(opt, tcp->dest) || in_range(opt, tcp->source)))
        goto out;

    __be16* o_p = in_range(opt, tcp->dest) ? &tcp->dest : &tcp->source;

    print("IN", "(%u ==> %u)", bpf_ntohs(*o_p), opt->in_p);
    *o_p = bpf_htons(opt->in_p);
    bpf_csum_diff(0, 0, (void*)tcp, tcp->doff * 4, 0);

out:
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
