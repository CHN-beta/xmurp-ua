#include <linux/module.h>
#include <linux/version.h>
#include <linux/kmod.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/moduleparam.h>
#include <linux/time.h>

const static unsigned char* str_ua_begin = "User-Agent: ";
const static unsigned char* str_ua_end = "\r\n";
const static unsigned char* str_head_end = "\r\n\r\n";
static unsigned char str_ua_rkp[7];

time_t now(void)
{
    struct timespec* ts = kmalloc(sizeof(struct timespec), GFP_KERNEL);
    time_t rtn;
    getnstimeofday(ts);
    rtn = ts -> tv_sec;
    kfree(ts);
#ifdef RKP_DEBUG
    printk("now %lu\n", ts -> tv_sec);
#endif
    return rtn;
}

#ifdef RKP_DEBUG
void skb_print(struct sk_buff* skb)
{
    printk("skb_print:\n");
    printk("\tport: %u %u\n", ntohs(tcp_hdr(skb) -> source), ntohs(tcp_hdr(skb) -> dest));
    printk("\tseq: %u %u\n", ntohl(tcp_hdr(skb) -> seq), ntohl(tcp_hdr(skb) -> ack_seq));
    printk("\tsyn %d ack %d psh %d\n", tcp_hdr(skb) -> syn, tcp_hdr(skb) -> ack, tcp_hdr(skb) -> psh);
}
#endif