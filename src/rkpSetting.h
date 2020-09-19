#pragma once
#include "common.h"

static_assert(sizeof(int) == 4, "int is not 4 bit.");
static_assert(sizeof(unsigned long) >= sizeof(void*), "ulong is too short.");

static bool autocapture = true;
module_param(autocapture, bool, 0);

static char* str_preserve[128];
static unsigned n_str_preserve = 0;
module_param_array(str_preserve, charp, &n_str_preserve, 0);

static unsigned mark_capture = 0x100;
module_param(mark_capture, uint, 0);

static unsigned mark_ack = 0x200;
module_param(mark_ack, uint, 0);

static unsigned time_keepalive = 60;
module_param(time_keepalive, uint, 0);

static unsigned len_ua = 2;
module_param(len_ua, uint, 0);

static bool debug = false;
module_param(debug, bool, 0);

bool rkpSetting_capture(const struct sk_buff*);
// 检查一个 skb 仅按照 ip 和端口来看，是否应该被捕获

bool rkpSetting_ack(const struct sk_buff*);
// 检查一个 skb 是否是回应的包

bool rkpSetting_capture(const struct sk_buff* skb)
{
    if(!autocapture)
    {
        return (skb->mark & mark_capture) == mark_capture;
    }
    else
    {
        if(rkpSetting_ack(skb))
            return true;
        if(ip_hdr(skb)->protocol != IPPROTO_TCP)
            return false;
        else if(ntohs(tcp_hdr(skb)->dest) != 80)
            return false;
        else if
        (
            (ntohl(ip_hdr(skb)->saddr) & 0xFFFF0000) != (192 << 24) + (168 << 16) ||
            (ntohl(ip_hdr(skb)->daddr) & 0xFFFF0000) == (192 << 24) + (168 << 16)
        )
            return false;
        else
            return true;
    }
}
bool rkpSetting_ack(const struct sk_buff* skb)
{
    if(!autocapture)
    {
        return (skb->mark & mark_ack) == mark_ack;
    }
    else
    {
        if(ip_hdr(skb)->protocol != IPPROTO_TCP)
            return false;
        else if(ntohs(tcp_hdr(skb)->source) != 80)
            return false;
        else if
        (
            (ntohl(ip_hdr(skb)->daddr) & 0xFFFF0000) != (192 << 24) + (168 << 16) ||
            (ntohl(ip_hdr(skb)->saddr) & 0xFFFF0000) == (192 << 24) + (168 << 16)
        )
            return false;
        else
            return tcp_hdr(skb)->ack;
    }
}