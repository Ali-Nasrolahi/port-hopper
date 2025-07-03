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

#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, struct hopper_opt);
    __uint(max_entries, 100);
} config SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} logs SEC(".maps");

const struct event* unused __attribute__((unused));

static __always_inline int submit_event(struct __sk_buff* ctx, const struct iphdr* ip,
                                        const struct tcphdr* tcp, __be16 altered_port)
{
    struct event* e = (bpf_ringbuf_reserve(&logs, sizeof(struct event), 0));
    if (e) {
        e->ifindex = ctx->ifindex;
        e->ipv4_src = ip->saddr;
        e->ipv4_dest = ip->daddr;
        e->port_src = tcp->source;
        e->port_dest = tcp->dest;
        e->port_alter = altered_port;
        bpf_ringbuf_submit(e, 0);
        return 0;
    }
    return -1;
}

static __always_inline int verify_n_parse(struct hopper_opt* opt, void* data, void* data_end,
                                          struct ethhdr** eth, struct iphdr** ip,
                                          struct tcphdr** tcp)
{
    *eth = data;
    *ip = (void*)(*eth + 1);

    if ((void*)((*ip) + 1) > data_end || (*ip)->ihl < 5 || (*ip)->ihl > 15) return -1;
    *tcp = (void*)(*ip) + (*ip)->ihl * 4;

    return (!opt || opt->max_p <= opt->min_p || (void*)(*tcp + 1) > data_end ||
            bpf_ntohs((*eth)->h_proto) != ETH_P_IP || (*ip)->protocol != IPPROTO_TCP);
}

SEC("tcx/egress")
int tc_port_hopper_egress(struct __sk_buff* ctx)
{
    struct ethhdr* eth;
    struct iphdr* ip;
    struct tcphdr* tcp;
    struct hopper_opt* opt;
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    int key = ctx->ifindex;
    opt = bpf_map_lookup_elem(&config, &key);

    if (verify_n_parse(opt, data, data_end, &eth, &ip, &tcp) ||
        !(tcp->dest == bpf_htons(opt->in_p) || tcp->source == bpf_htons(opt->in_p)))
        goto out;

    __be16* port_ref = tcp->dest == bpf_htons(opt->in_p) ? &tcp->dest : &tcp->source;
    __be16 new_port = bpf_htons((bpf_get_prandom_u32() % (opt->max_p - opt->min_p)) + opt->min_p);
    if (submit_event(ctx, ip, tcp, new_port)) bpf_printk("EG Failed to reserve event memory");
    *port_ref = new_port;

    // Attention: if egress checksum offload is not enabled, redo the checksum, just like ingress

out:
    return TC_ACT_OK;
}

static __always_inline int in_range(struct hopper_opt* opt, __be16 port)
{
    port = bpf_ntohs(port);
    return port < opt->max_p && port >= opt->min_p;
}

SEC("tcx/ingress")
int tc_port_hopper_ingress(struct __sk_buff* ctx)
{
    struct ethhdr* eth;
    struct iphdr* ip;
    struct tcphdr* tcp;
    struct hopper_opt* opt;
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    int key = ctx->ifindex;
    opt = bpf_map_lookup_elem(&config, &key);

    if (verify_n_parse(opt, data, data_end, &eth, &ip, &tcp) ||
        !(in_range(opt, tcp->dest) || in_range(opt, tcp->source)))
        goto out;

    __be16* ref_port = in_range(opt, tcp->dest) ? &tcp->dest : &tcp->source;
    __be16 save = *ref_port;
    if (submit_event(ctx, ip, tcp, save)) bpf_printk("IG Failed to reserve event memory");

    *ref_port = bpf_htons(opt->in_p);
    int off = ETH_HLEN + (ip->ihl * 4) + offsetof(struct tcphdr, check);
    bpf_l4_csum_replace(ctx, off, save, *ref_port, sizeof(save) | BPF_F_PSEUDO_HDR);

out:
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
