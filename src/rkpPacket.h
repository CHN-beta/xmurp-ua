#pragma once
#include "common.h"

struct rkpPacket
// 存储一个个数据包的类，完全被 rkpStream 和 rkpManager 包裹
{
    struct rkpPacket *prev, *next;
    struct sk_buff* skb;
    u_int8_t sid;
    u_int32_t lid[3];
};

struct rkpPacket* rkpPacket_new(struct sk_buff*);
void rkpPacket_send(struct rkpPacket*);
void rkpPacket_delete(struct rkpPacket*);
void rkpPacket_drop(struct rkpPacket*);

unsigned char* rkpPacket_appBegin(struct rkpPacket*);
unsigned char* rkpPacket_appEnd(struct rkpPacket*);
unsigned rkpPacket_appLen(struct rkpPacket*);
int32_t rkpPacket_seq(struct rkpPacket*);
int32_t rkpPacket_ack(struct rkpPacket*);
u_int32_t rkpPacket_sip(struct rkpPacket*);
u_int32_t rkpPacket_dip(struct rkpPacket*);
u_int32_t rkpPacket_sport(struct rkpPacket*);
u_int32_t rkpPacket_dport(struct rkpPacket*);
bool rkpPacket_psh(struct rkpPacket*);
bool rkpPacket_syn(struct rkpPacket*);

void rkpPacket_csum(struct rkpPacket*);
bool __rkpPacket_makeWriteable(struct rkpPacket*);

struct rkpPacket* rkpPacket_new(struct sk_buff* skb)
{
    struct rkpPacket* rkpp = rkpMalloc(sizeof(struct rkpPacket));
    if(rkpp == 0)
        return 0;
    rkpp -> prev = rkpp -> next = 0;
    rkpp -> skb = skb;
    rkpp -> sid = (rkpPacket_sport(rkpp) + rkpPacket_dport(rkpp)) & 0xFF;
    rkpp -> lid[0] = rkpPacket_sip(rkpp);
    rkpp -> lid[1] = rkpPacket_dip(rkpp);
    rkpp -> lid[2] = (rkpPacket_sport(rkpp) << 16) + rkpPacket_dport(rkpp);
    if(!__rkpPacket_makeWriteable(rkpp))
    {
        rkpFree(rkpp);
        return 0;
    }
    return p;
}
void rkpPacket_send(struct rkpPacket* p)
{
    if(dev_queue_xmit(p -> skb))
    {
        printk("rkp-ua: rkpPacket_new: Send failed. Drop it.\n");
        kfree_skb(p -> skb);
    }
    rkpFree(p);
}
void rkpPacket_delete(struct rkpPacket* p)
{
    rkpFree(p);
}
void rkpPacket_drop(struct rkpPacket* p)
{
    kfree_skb(p -> skb);
    rkpFree(p);
}

unsigned char* rkpPacket_appBegin(struct rkpPacket* p)
{
    return ((unsigned char*)tcp_hdr(p -> skb)) + tcp_hdr(p -> skb) -> doff * 4;
}
unsigned char* rkpPacket_appEnd(struct rkpPacket* p)
{
    return ((unsigned char*)ip_hdr(p -> skb)) + ntohs(ip_hdr(p -> skb) -> tot_len);
}
unsigned rkpPacket_appLen(struct rkpPacket* p)
{
    return ntohs(ip_hdr(p -> skb) -> tot_len) - ip_hdr(p -> skb) -> ihl * 4 - tcp_hdr(p -> skb) -> doff * 4;
}
int32_t rkpPacket_seq(struct rkpPacket* p)
{
    return ntohl(tcp_hdr(p -> skb) -> seq);
}
int32_t rkpPacket_ack(struct rkpPacket* p)
{
    return ntohl(tcp_hdr(p -> skb) -> ack);
}
u_int32_t rkpPacket_sip(struct rkpPacket* rkpp)
{
    return ntohl(ip_hdr(rkpp -> skb) -> saddr);
}
u_int32_t rkpPacket_dip(struct rkpPacket* rkpp)
{
    return ntohl(ip_hdr(rkpp -> skb) -> daddr);
}
u_int16_t rkpPacket_sport(struct rkpPacket* rkpp)
{
    return ntohs(tcp_hdr(rkpp -> skb) -> source);
}
u_int32_t rkpPacket_dport(struct rkpPacket* rkpp)
{
    return ntohs(tcp_hdr(rkpp -> skb) -> dest);
}
bool rkpPacket_psh(struct rkpPacket* rkpp)
{
    return tcp_hdr(rkpp -> skb) -> psh;
}
bool rkpPacket_syn(struct rkpPacket* rkpp)
{
    return tcp_hdr(rkpp -> skb) -> syn;
}

void rkpPacket_csum(struct rkpPacket* p)
{
    struct iphdr* iph = ip_hdr(p -> skb);
    struct tcphdr* tcph = tcp_hdr(p -> skb);
    tcph -> check = 0;
    iph -> check = 0;
    iph -> check = ip_fast_csum((unsigned char*)iph, iph -> ihl);
    p -> skb -> csum = skb_checksum(p -> skb, iph -> ihl * 4, ntohs(iph -> tot_len) - iph -> ihl * 4, 0);
    tcph -> check = csum_tcpudp_magic(iph -> saddr, iph -> daddr, ntohs(iph -> tot_len) - iph -> ihl * 4, IPPROTO_TCP, p -> skb -> csum);
}

bool __rkpPacket_makeWriteable(struct rkpPacket* rkpp)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	if(skb_ensure_writable(rkpp -> skb, rkpPacket_appEnd(rkpp) - (unsigned char*)rkpp -> skb -> data) || rkpp -> skb -> data == 0)
#else
	if(!skb_make_writable(rkpp -> skb, rkpPacket_appEnd(rkpp)- (unsigned char*)rkpp -> skb -> data) || rkpp -> skb -> data == 0)
#endif
    {
        printk("rkp-ua: rkpPacket_makeWriteable: failed.\n");
        return false;
    }
    return true;
}