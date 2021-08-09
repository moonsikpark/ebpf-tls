#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

struct tls_record_header {
    uint8_t content_type;
    uint8_t ver_major;
    uint8_t ver_minor;
    uint16_t len;
} __attribute__((packed));

int tls_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if (!(data + sizeof(*eth) <= data_end)) {
        goto pass;
    }

    struct iphdr *ip = data + sizeof(*eth);

    if (!(data + sizeof(*eth) + sizeof(*ip) <= data_end)) {
        goto pass;
    }

    if (!(ip->version == 4 && ip->protocol == IPPROTO_TCP)) {
        goto pass;
    }

    struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);

    if (!(data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) <= data_end)) {
        goto pass;
    }
    if (!(tcp->source == ntohs(443) || tcp->dest == ntohs(443))) {
        goto pass;
    }

    bpf_trace_printk("Got TCP packet from: %d to: %d\n", htons(tcp->source), htons(tcp->dest));

    struct tls_record_header *record_header = data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) + sizeof(*tcp);

    if (!(data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) + sizeof(*tcp) + sizeof(*record_header) <= data_end)) {
        goto pass;
    }

    bpf_trace_printk("TLS packet: %02X %02X %02X\n", record_header->content_type, record_header->ver_major, record_header->ver_minor);

    bpf_trace_printk("TLS packet: %04X\n", record_header->len);

    pass:
        return XDP_PASS;

}
