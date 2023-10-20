import argparse

from bcc import BPF


argParser = argparse.ArgumentParser()
argParser.add_argument("-p","--port", help="The port that is used for decapsulation", default=7932)
argParser.add_argument("-s","--strip", help="Bytes to strip", default=54)
argParser.add_argument("-i","--input-interface", help="The interface to read from", required=True)
args = argParser.parse_args()

device = args.input_interface
strip_bytes = args.strip
port = args.port



XDP_APP = r"""
/*
 * strip-hp-erm.c
 *
 * Strip 54 bytes from IPV4 UDP packets coming in on port 7932
 * that are long enough such that AF_PACKET will load balance
 * based on the inner payload and Zeek will only see that, too.
 *
 * ETH(14)/IP(20)/UDP(8)/HP ERM(12) header
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

int strip_ipv4_hp_erm(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;

  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    return XDP_DROP;

  /*if (eth->h_proto != bpf_htons(ETH_P_IP)) // Ignore non-IPv4 packets
    return XDP_PASS;

  struct iphdr *ip = (void *)eth + sizeof(struct ethhdr);

  if (ip->protocol != IPPROTO_UDP) // Ignore non-UDP packets
    return XDP_PASS;

  struct udphdr *udp = (void *)ip + (ip->ihl << 2);
  if ((void *)udp + sizeof(struct udphdr) > data_end)
    return XDP_DROP;

  if (udp->dest != bpf_htons(7932))
    return XDP_PASS;

  // Do we even have enough bytes?
  if (data + 54 > data_end)
    return XDP_PASS;

  // Okay. It's a UDP packet to to 7932, strip the header.
  // bpf_trace_printk("Stripping HP ERM!\n");
  bpf_xdp_adjust_head(ctx,54);
  return XDP_PASS;*/
}
"""



bpf = BPF(text=XDP_APP, debug=0)
fn = bpf.load_func("strip_ipv4_hp_erm", BPF.XDP)
bpf.attach_xdp(device, fn, 0)


try:
    bpf.trace_print()
except KeyboardInterrupt:
    print("interupt")
finally:
    print("removing")
    bpf.remove_xdp(device)

