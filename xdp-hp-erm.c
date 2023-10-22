#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdint.h>

//port for HP ERM Protocol 
uint16_t port = 7932;
//bytes to strip from the beginning
int bytes_strip = 54;

int strip_ipv4_hp_erm(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;

  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    return XDP_DROP;

  if (eth->h_proto != bpf_htons(ETH_P_IP)) // Ignore non-IPv4 packets
    return XDP_PASS;

  struct iphdr *ip = (void *)eth + sizeof(struct ethhdr);

  if (ip->protocol != IPPROTO_UDP) // Ignore non-UDP packets
    return XDP_PASS;

  struct udphdr *udp = (void *)ip + (ip->ihl << 2);
  if ((void *)udp + sizeof(struct udphdr) > data_end)
    return XDP_DROP;

  if (udp->dest != bpf_htons(port))
    return XDP_PASS;

  if (data + 54 > data_end)
    return XDP_PASS;

  bpf_xdp_adjust_head(ctx,bytes_strip);
  return XDP_PASS;
}
