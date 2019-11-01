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
#include <asm/limits.h>
#include <linux/time.h>

const unsigned char* str_ua = "User-Agent: ";
const unsigned char* str_end = "\r\n\r\n";
const unsigned char* str_win = "Windows NT";

u_int8_t mode_advanced = 0;
module_param(mode_advanced, bool, 0);
u_int8_t mode_winPreserve = 0;
module_param(mode_winPreserve, bool, 0);

u_int32_t mark_capture = 0x100;
module_param(mark_capture, uint, 0);
u_int32_t mark_request = 0x200;
module_param(mark_request, uint, 0);
u_int32_t mark_first = 0x400;
module_param(mark_first, uint, 0);
u_int32_t mark_winPreserve = 0x800;
module_param(mark_winPreserve, uint, 0);

u_int8_t rkpSettings_capture(struct sk_buff*);
u_int8_t rkpSettings_request(struct sk_buff*);
u_int8_t rkpSettings_first(struct sk_buff*);
u_int8_t rkpSettings_winPreserve(struct sk_buff*);

u_int8_t rkpSettings_capture(struct sk_buff* skb)
{
    if(mode_advanced)
        return skb -> mark & mark_capture == mark_capture;
    else
    {
        if(ip_hdr(skb) -> protocol != IPPROTO_TCP)
            return 0;
        else if(tcp_hdr(skb) -> dport == 80)
            return 1;
        else if(tcp_hdr(skb) -> sport == 80 && tcp_hdr(skb) -> ack)
            return 1;
        else
            return 0;
    }
}

u_int8_t rkpSettings_request(struct sk_buff* skb)
{
    if(mode_advanced)
        return skb -> mark & mark_request == mark_request;
    else
        return ip_hdr(skb) -> daddr == 80;
}

u_int8_t rkpSettings_first(struct sk_buff* skb)
{
    if(mode_advanced)
        return skb -> mark & mark_first == mark_first;
    else
        return tcp_hdr(skb) -> syn && !tcp_hdr(skb) -> ack;
}

u_int8_t rkpSettings_winPreserve(struct sk_buff* skb)
{
    if(mode_advanced)
        return skb -> mark & mark_winPreserve == mark_winPreserve;
    else
        return mode_winPreserve;
}

time_t now()
{
    struct timespec* ts;
    getnstimeofday(ts);
    return ts -> tv_sec;
}
