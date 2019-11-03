#include "common.h"

static u_int8_t mode_advanced = 0;
module_param(mode_advanced, bool, 0);

static char* str_preserve[128];
static unsigned n_str_preserve = 0;
module_param_array(str_preserve, charp, &n_str_preserve, 0);

static u_int32_t mark_capture = 0x100;
module_param(mark_capture, uint, 0);
static u_int32_t mark_request = 0x200;
module_param(mark_request, uint, 0);
static u_int32_t mark_first = 0x400;
module_param(mark_first, uint, 0);
static u_int32_t mark_preserve = 0x800;
module_param(mark_preserve, uint, 0);

static unsigned time_keepalive = 1200
module_param(time_keepalive, uint, 0);

u_int8_t rkpSettings_capture(struct sk_buff*);
u_int8_t rkpSettings_request(struct sk_buff*);
u_int8_t rkpSettings_first(struct sk_buff*);
u_int8_t rkpSettings_preserve(struct sk_buff*);

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
u_int8_t rkpSettings_preserve(struct sk_buff* skb)
{
    if(mode_advanced)
        return skb -> mark & mark_preserve == mark_preserve;
    else
        return 1;
}