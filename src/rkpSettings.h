#pragma once
#include "common.h"

_Static_assert(sizeof(int) == 4, "int is not 4 bit.");
_Static_assert(sizeof(unsigned long) >= sizeof(void*), "ulong is too short.");

static bool autocapture = true;
module_param(autocapture, bool, 0);

static char* str_preserve[128];
static unsigned n_str_preserve = 0;
module_param_array(str_preserve, charp, &n_str_preserve, 0);

static unsigned mark_capture = 0x100;
module_param(mark_capture, uint, 0);

static unsigned time_keepalive = 1200;
module_param(time_keepalive, uint, 0);

bool rkpSettings_capture(const struct sk_buff*);

bool rkpSettings_capture(const struct sk_buff* skb)
{
    if(!autocapture)
    {
        return (skb -> mark & mark_capture) == mark_capture;
    }
    else
    {
        if(ip_hdr(skb) -> protocol != IPPROTO_TCP)
            return false;
        else if(ntohs(tcp_hdr(skb) -> dest) != 80)
            return false;
        else if((ntohl(ip_hdr(skb) -> saddr) & 0xFFFF0000) != (192 << 24) + (168 << 16)
                || (ntohl(ip_hdr(skb) -> daddr) & 0xFFFF0000) == (192 << 24) + (168 << 16))
            return false;
        else
            return true;
    }
}