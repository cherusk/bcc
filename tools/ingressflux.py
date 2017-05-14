#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# Copyright (C) 2017  Matthias Tafelmeier
#
# ingressflux is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# ingressflux is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


from bcc import BPF
import argparse
import ctypes as ct
import time
from struct import pack
from socket import inet_ntop, AF_INET, AF_INET6


#todo
examples = """examples:
    ./ingressflux # 
"""

parser = argparse.ArgumentParser(
    description="Trace flows traversing down the network stack",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-i", "--interval", default=3, type=int,
    help="interval of run in seconds")
args = parser.parse_args()


bpf_text = """
#define KBUILD_MODNAME "FOO"
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <linux/skbuff.h>
#include <linux/dynamic_debug.h>
#include <linux/module.h>

struct ipv4_data_t {
    int cpu;
    int tgt_cpu;
    u16 path;
    u64 saddr;
    u64 daddr;
    u64 lport;
    u64 dport;
    unsigned int vol;
    u8 prot;
};

struct ipv6_data_t {
    int cpu;
    int tgt_cpu;
    u16 path;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 lport;
    u64 dport;
    unsigned int vol;
    char prot[32];
};

BPF_PERF_OUTPUT(ipv4_flows);
BPF_PERF_OUTPUT(ipv6_flows);

#define DIRECT            1
#define LOCAL_STEERED     2

#define DATA_INIT_COMMON(data, curr_cpu, tgt_cpu, \
                         path, data_len, lport, dport) \
                         data.cpu = curr_cpu; \
                         data.tgt_cpu = tgt_cpu; \
                         data.path = path; \
                         data.vol = data_len; \
                         data.lport = lport; \
                         data.dport = ntohs(dport);

static int tracing_prefetch_sk(struct sk_buff *skb)
{
    const struct iphdr *iph = ip_hdr(skb);

    bpf_trace_printk("%p\\n", iph);

    return 0;
}

static int tracing_core(struct pt_regs *ctx, struct sk_buff *skb,
                        int tgt_cpu, u16 path)
{
    struct sk_buff *_skb = NULL;
    bpf_probe_read(&_skb, sizeof(_skb), &skb);

    int nh_off = BPF_LL_OFF + ETH_HLEN;
    u8 ip_proto;
    bpf_skb_load_bytes(_skb, nh_off + offsetof(struct iphdr, protocol),
                                &ip_proto, sizeof(ip_proto));

    if (ip_proto != IPPROTO_TCP) {
        return 0;
    }

    int curr_cpu = bpf_get_smp_processor_id();

    // get flow details
    u16 lport = 0, dport = 0;
    unsigned int data_len = 0;

    bpf_skb_load_bytes(_skb, nh_off + offsetof(struct tcphdr, source),
                        &lport, sizeof(lport));
    bpf_skb_load_bytes(_skb, nh_off + offsetof(struct tcphdr, dest),
                        &dport, sizeof(dport));
    bpf_probe_read(&data_len, sizeof(data_len), &_skb->data_len);


    if (skb->protocol == htons(ETH_P_IP)) {
        bpf_trace_printk("IN4%d\\n", path);
        struct ipv4_data_t data4 = {};
        DATA_INIT_COMMON(data4, curr_cpu, tgt_cpu, path,
                         data_len, lport, dport);

        bpf_probe_read(&data4.prot, sizeof(data4.prot),
            &ip_proto);
        bpf_skb_load_bytes(_skb, nh_off + offsetof(struct iphdr, saddr),
                        &data4.saddr, sizeof(u32));
        bpf_skb_load_bytes(_skb, nh_off + offsetof(struct iphdr, daddr),
                        &data4.daddr, sizeof(u32));
        ipv4_flows.perf_submit(ctx, &data4, sizeof(data4));
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        bpf_trace_printk("IN6%d\\n", path);
    }
    // drop other

    return 0;
}

int trace_rx_qu_direct(struct pt_regs *ctx, struct sk_buff *skb)
{
    tracing_core(ctx, skb, -1, DIRECT);
    return 0;
}

int trace_rx_steered(struct pt_regs *ctx, struct sk_buff *skb, int cpu)
{
    tracing_core(ctx, skb, cpu, LOCAL_STEERED);
    return 0;
}
"""

# entry data
class Data_ipv4(ct.Structure):
    _fields_ = [
        ("cpu", ct.c_int),
        ("tgt_cpu", ct.c_int),
        ("path", ct.c_ushort),
        ("saddr", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("lport", ct.c_ulonglong),
        ("dport", ct.c_ulonglong),
        ("vol", ct.c_uint),
        ("prot", ct.c_char * 32)
    ]

class Data_ipv6(ct.Structure):
    _fields_ = [
        ("cpu", ct.c_int),
        ("tgt_cpu", ct.c_int),
        ("path", ct.c_ushort),
        ("saddr", (ct.c_ulonglong * 2)),
        ("daddr", (ct.c_ulonglong * 2)),
        ("lport", ct.c_ulonglong),
        ("dport", ct.c_ulonglong),
        ("vol", ct.c_uint),
        ("prot", ct.c_char * 32)
    ]


flow_ctxs = {}

b = BPF(text=bpf_text)
b.attach_kprobe(event="__netif_receive_skb", fn_name="trace_rx_qu_direct")
b.attach_kprobe(event="enqueue_to_backlog", fn_name="trace_rx_steered")

def gather_ipv4_flow(cpu, data, size):
    pass

def gather_ipv6_flow(cpu, data, size):
    pass

b['ipv4_flows'].open_perf_buffer(gather_ipv4_flow)
b['ipv6_flows'].open_perf_buffer(gather_ipv6_flow)

t_end = time.time() + args.interval
print t_end
while time.time() < t_end:
    b.trace_print()
    print time.time()
