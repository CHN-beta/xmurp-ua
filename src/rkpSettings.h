#include "common.h"

static bool mode_advanced = false;
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

static unsigned time_keepalive = 1200;
module_param(time_keepalive, uint, 0);

bool rkpSettings_capture(const struct sk_buff*);
bool rkpSettings_request(const struct sk_buff*);
bool rkpSettings_first(const struct sk_buff*);
bool rkpSettings_preserve(const struct sk_buff*);

bool rkpSettings_capture(const struct sk_buff* skb)
{

    if(ntohl(ip_hdr(skb) -> daddr) != (216 << 24) + (24 << 16) + (178 << 8) + 192 && ntohl(ip_hdr(skb) -> saddr) != (216 << 24) + (24 << 16) + (178 << 8) + 192)
        return false;

    if(mode_advanced)
        return (skb -> mark & mark_capture) == mark_capture;
    else
    {
        if(ip_hdr(skb) -> protocol != IPPROTO_TCP)
            return false;
        else if(ntohs(tcp_hdr(skb) -> dest) == 80)
            return true;
        else if(ntohs(tcp_hdr(skb) -> source) == 80 && tcp_hdr(skb) -> ack)
            return true;
        else
            return false;
    }
}
bool rkpSettings_request(const struct sk_buff* skb)
{
    if(mode_advanced)
        return (skb -> mark & mark_request) == mark_request;
    else
        return ntohs(tcp_hdr(skb) -> dest) == 80;
}
bool rkpSettings_first(const struct sk_buff* skb)
{
    if(mode_advanced)
        return (skb -> mark & mark_first) == mark_first;
    else
        return tcp_hdr(skb) -> syn && !tcp_hdr(skb) -> ack;
}
bool rkpSettings_preserve(const struct sk_buff* skb)
{
    if(mode_advanced)
        return (skb -> mark & mark_preserve) == mark_preserve;
    else
        return true;
}