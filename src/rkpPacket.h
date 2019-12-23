#pragma once
#include "common.h"

struct rkpPacket
// 存储一个个数据包的类，完全被 rkpStream 包裹
{
    struct rkpPacket *prev, *next;
    struct sk_buff* skb;
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
bool rkpPacket_psh(struct rkpPacket*);

void rkpPacket_csum(struct rkpPacket*);
bool rkpPacket_makeWriteable(struct rkpPacket*);

struct rkpPacket* rkpPacket_new(struct sk_buff* skb)
{
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpPacket_new start.\n");
#endif
    struct rkpPacket* p = rkpMalloc(sizeof(struct rkpPacket));
    if(p != 0)
    {
        p -> prev = p -> next = 0;
        p -> skb = skb;
    }
    else
        printk("rkp-ua: rkpPacket_new: malloc failed.\n");
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpPacket_new end.\n");
#endif
    return p;
}
void rkpPacket_send(struct rkpPacket* p)
{
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpPacket_send start.\n");
#endif
    if(dev_queue_xmit(p -> skb))
    {
        printk("rkp-ua: rkpPacket_new: Send failed. Drop it.\n");
        kfree_skb(p -> skb);
    }
    rkpFree(p);
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpPacket_send end.\n");
#endif
}
void rkpPacket_delete(struct rkpPacket* p)
{
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpPacket_delete start.\n");
#endif
    rkpFree(p);
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpPacket_delete end.\n");
#endif
}
void rkpPacket_drop(struct rkpPacket* p)
{
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpPacket_drop start.\n");
#endif
    kfree_skb(p -> skb);
    rkpFree(p);
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpPacket_drop end.\n");
#endif 
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
bool rkpPacket_psh(struct rkpPacket* rkpp)
{
    return tcp_hdr(rkpp -> skb) -> psh;
}

void rkpPacket_csum(struct rkpPacket* p)
{
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpPacket_csum start.\n");
#endif
    struct iphdr* iph = ip_hdr(p -> skb);
    struct tcphdr* tcph = tcp_hdr(p -> skb);
    tcph -> check = 0;
    iph -> check = 0;
    iph -> check = ip_fast_csum((unsigned char*)iph, iph -> ihl);
    p -> skb -> csum = skb_checksum(p -> skb, iph -> ihl * 4, ntohs(iph -> tot_len) - iph -> ihl * 4, 0);
    tcph -> check = csum_tcpudp_magic(iph -> saddr, iph -> daddr, ntohs(iph -> tot_len) - iph -> ihl * 4, IPPROTO_TCP, p -> skb -> csum);
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpPacket_csum end.\n");
#endif
}

bool rkpPacket_makeWriteable(struct rkpPacket* rkpp)
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