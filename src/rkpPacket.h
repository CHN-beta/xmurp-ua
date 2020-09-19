#pragma once
#include "common.h"

struct rkpPacket
// 存储一个个数据包的类，完全被 rkpStream 和 rkpManager 包裹

{
    struct rkpPacket *prev, *next;
    // 双向链表

    struct sk_buff* skb;

    u_int8_t sid;
    // 取两端口之和的低8位，作为 hash 表的键

    u_int32_t lid[3];
    // 对于非 ack 的包，分别为源地址、目标地址、源端口、目标端口，作为流的唯一标识。
    // 对于 ack，则是目标地址、源地址、目标端口、源端口

    bool ack;
};

struct rkpPacket* rkpPacket_new(struct sk_buff*, bool);
void rkpPacket_send(struct rkpPacket*);

void rkpPacket_delete(struct rkpPacket*);
// 释放一个 packet 对象，不会释放附属的 skb

void rkpPacket_drop(struct rkpPacket*);
// 释放一个 packet 对象，同时释放附属的 skb

unsigned char* rkpPacket_appBegin(const struct rkpPacket*);
unsigned char* rkpPacket_appEnd(const struct rkpPacket*);
unsigned rkpPacket_appLen(const struct rkpPacket*);
// 得到 skb 应用层内容的位置和长度

int32_t rkpPacket_seq(const struct rkpPacket*, const int32_t);
int32_t rkpPacket_seqAck(const struct rkpPacket*, const int32_t);
u_int32_t rkpPacket_sip(const struct rkpPacket*);
u_int32_t rkpPacket_dip(const struct rkpPacket*);
u_int16_t rkpPacket_sport(const struct rkpPacket*);
u_int16_t rkpPacket_dport(const struct rkpPacket*);
bool rkpPacket_psh(const struct rkpPacket*);
bool rkpPacket_syn(const struct rkpPacket*);
bool rkpPacket_ack(const struct rkpPacket*);
// 得到 skb 中的其它信息

void rkpPacket_csum(struct rkpPacket*);
// 重新计算 ip 和 tcp 的校验和

bool __rkpPacket_makeWriteable(struct rkpPacket*);
// 使得 skb 可以写。有时，内核不会将包的内容按照顺序紧密放置，而是共享其它部分的资源（只丢个指针在 skb 里）。
// 需要这一步来保证内容全部复制到 skb 里，可以自由修改

void rkpPacket_makeOffset(const struct rkpPacket*, int32_t*);
// 发出一个包后，该流的序列号的偏移需要相应修改。在发出这个包前，调用这个函数来修改流的序列号偏移

void rkpPacket_insert_auto(struct rkpPacket**, struct rkpPacket*, int32_t offset);
// 在链表中插入一个包，自动根据序列号确定插入的位置
// 假定包的指向前后位置的指针已经置零

void rkpPacket_insert_begin(struct rkpPacket**, struct rkpPacket*);
void rkpPacket_insert_end(struct rkpPacket**, struct rkpPacket*);
// 在链表的相应位置插入一个包
// 假定包的指向前后位置的指针已经置零

struct rkpPacket* rkpPacket_pop_begin(struct rkpPacket**);
struct rkpPacket* rkpPacket_pop_end(struct rkpPacket**);
// 取出流的指定位置的包，假定流不空

unsigned rkpPacket_num(struct rkpPacket**);
// 返回链表中包的数目

void rkpPacket_sendl(struct rkpPacket**);
void rkpPacket_deletel(struct rkpPacket**);
void rkpPacket_dropl(struct rkpPacket**);
// 将整个链表 send、delete 或 drop

struct rkpPacket* rkpPacket_new(struct sk_buff* skb, bool ack)
{
    struct rkpPacket* rkpp = rkpMalloc(sizeof(struct rkpPacket));
    if(rkpp == 0)
        return 0;
    rkpp->prev = rkpp->next = 0;
    rkpp->skb = skb;
    rkpp->ack = ack;
    rkpp->sid = (rkpPacket_sport(rkpp) + rkpPacket_dport(rkpp)) & 0xFF;
    if(!ack)
    {
        rkpp->lid[0] = rkpPacket_sip(rkpp);
        rkpp->lid[1] = rkpPacket_dip(rkpp);
        rkpp->lid[2] = (rkpPacket_sport(rkpp) << 16) + rkpPacket_dport(rkpp);
    }
    else
    {
        rkpp->lid[0] = rkpPacket_dip(rkpp);
        rkpp->lid[1] = rkpPacket_sip(rkpp);
        rkpp->lid[2] = (rkpPacket_dport(rkpp) << 16) + rkpPacket_sport(rkpp);
    }
    if(!__rkpPacket_makeWriteable(rkpp))
    {
        rkpFree(rkpp);
        return 0;
    }
    return rkpp;
}
void rkpPacket_send(struct rkpPacket* rkpp)
{
    if(dev_queue_xmit(rkpp->skb))
    {
        printk("rkp-ua: rkpPacket_new: Send failed. Drop it.\n");
        kfree_skb(rkpp->skb);
    }
    rkpFree(rkpp);
}
void rkpPacket_delete(struct rkpPacket* rkpp)
{
    rkpFree(rkpp);
}
void rkpPacket_drop(struct rkpPacket* rkpp)
{
    kfree_skb(rkpp->skb);
    rkpFree(rkpp);
}

unsigned char* rkpPacket_appBegin(const struct rkpPacket* rkpp)
{
    return ((unsigned char*)tcp_hdr(rkpp->skb)) + tcp_hdr(rkpp->skb)->doff * 4;
}
unsigned char* rkpPacket_appEnd(const struct rkpPacket* rkpp)
{
    return ((unsigned char*)ip_hdr(rkpp->skb)) + ntohs(ip_hdr(rkpp->skb)->tot_len);
}
unsigned rkpPacket_appLen(const struct rkpPacket* rkpp)
{
    return ntohs(ip_hdr(rkpp->skb)->tot_len) - ip_hdr(rkpp->skb)->ihl * 4 - tcp_hdr(rkpp->skb)->doff * 4;
}
int32_t rkpPacket_seq(const struct rkpPacket* rkpp, const int32_t offset)
{
    return (int32_t)ntohl(tcp_hdr(rkpp->skb)->seq) - offset;
}
int32_t rkpPacket_seqAck(const struct rkpPacket* rkpp, const int32_t offset)
{
    return (int32_t)ntohl(tcp_hdr(rkpp->skb)->ack_seq) - offset;
}
u_int32_t rkpPacket_sip(const struct rkpPacket* rkpp)
{
    return ntohl(ip_hdr(rkpp->skb)->saddr);
}
u_int32_t rkpPacket_dip(const struct rkpPacket* rkpp)
{
    return ntohl(ip_hdr(rkpp->skb)->daddr);
}
u_int16_t rkpPacket_sport(const struct rkpPacket* rkpp)
{
    return ntohs(tcp_hdr(rkpp->skb)->source);
}
u_int16_t rkpPacket_dport(const struct rkpPacket* rkpp)
{
    return ntohs(tcp_hdr(rkpp->skb)->dest);
}
bool rkpPacket_psh(const struct rkpPacket* rkpp)
{
    return tcp_hdr(rkpp->skb)->psh;
}
bool rkpPacket_syn(const struct rkpPacket* rkpp)
{
    return tcp_hdr(rkpp->skb)->syn;
}
bool rkpPacket_ack(const struct rkpPacket* rkpp)
{
    return tcp_hdr(rkpp->skb)->ack;
}

void rkpPacket_csum(struct rkpPacket* rkpp)
{
    struct iphdr* iph = ip_hdr(rkpp->skb);
    struct tcphdr* tcph = tcp_hdr(rkpp->skb);
    tcph->check = 0;
    iph->check = 0;
    rkpp->skb->csum = skb_checksum
    (
        rkpp->skb,
        iph->ihl * 4,
        ntohs(iph->tot_len) - iph->ihl * 4,
        0
    );
    iph->check = ip_fast_csum((unsigned char*)iph, iph->ihl);
    tcph->check = csum_tcpudp_magic
    (
        iph->saddr,
        iph->daddr,
        ntohs(iph->tot_len) - iph->ihl * 4,
        IPPROTO_TCP,
        rkpp->skb->csum
    );
}

bool __rkpPacket_makeWriteable(struct rkpPacket* rkpp)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	if(skb_ensure_writable(rkpp->skb, rkpPacket_appEnd(rkpp) - (unsigned char*)rkpp->skb->data) || rkpp->skb->data == 0)
#else
	if(!skb_make_writable(rkpp->skb, rkpPacket_appEnd(rkpp) - (unsigned char*)rkpp->skb->data) || rkpp->skb->data == 0)
#endif
    {
        printk("rkp-ua: rkpPacket_makeWriteable: failed.\n");
        return false;
    }
    return true;
}

void rkpPacket_makeOffset(const struct rkpPacket* rkpp, int32_t* offsetp)
{
    *offsetp = rkpPacket_seq(rkpp, 0) + rkpPacket_appLen(rkpp);
}

void rkpPacket_insert_auto(struct rkpPacket** buff, struct rkpPacket* rkpp, int32_t offset)
{
    // 如果链表是空的，那么就直接加进去
    if(*buff == 0)
        *buff = rkpp;

    // 又或者，要插入的包需要排到第一个
    else if(rkpPacket_seq(*buff, offset) >= rkpPacket_seq(rkpp, offset))
    {
        (*buff)->prev = rkpp;
        rkpp->next = *buff;
        *buff = rkpp;
    }
    // 接下来寻找最后一个序列号小于 rkpp 的包，插入到它的后面。
    else
    {
        struct rkpPacket* rkpp2 = *buff;
        while(rkpp2->next != 0 && rkpPacket_seq(rkpp2->next, offset) < rkpPacket_seq(rkpp, offset))
            rkpp2 = rkpp2->next;
        rkpp->next = rkpp2->next;
        rkpp->prev = rkpp2;
        if(rkpp->next != 0)
            rkpp->next->prev = rkpp;
        rkpp2->next = rkpp;
    }
}
void rkpPacket_insert_begin(struct rkpPacket** buff, struct rkpPacket* rkpp)
{
    if(*buff == 0)
        *buff = rkpp;
    else
    {
        (*buff)->prev = rkpp;
        rkpp->next = *buff;
        *buff = rkpp;
    }
}
void rkpPacket_insert_end(struct rkpPacket** buff, struct rkpPacket* rkpp)
{
    if(*buff == 0)
        *buff = rkpp;
    else
    {
        struct rkpPacket* rkpp2 = *buff;
        while(rkpp2->next != 0)
            rkpp2 = rkpp2->next;
        rkpp2->next = rkpp;
        rkpp->prev = rkpp2;
    }
}
struct rkpPacket* rkpPacket_pop_begin(struct rkpPacket** buff)
{
    struct rkpPacket* rkpp = *buff;
    if(rkpp->next == 0)
        *buff = 0;
    else
    {
        *buff = rkpp->next;
        rkpp->next = 0;
        (*buff)->prev = 0;
    }
    return rkpp;
}
struct rkpPacket* rkpPacket_pop_end(struct rkpPacket** buff)
{
    struct rkpPacket* rkpp = *buff;
    while(rkpp->next != 0)
        rkpp = rkpp->next;
    if(rkpp == *buff)
        *buff = 0;
    else
    {
        rkpp->prev->next = 0;
        rkpp->prev = 0;
    }
    return rkpp;
}
unsigned rkpPacket_num(struct rkpPacket** buff)
{
    unsigned n = 0;
    const struct rkpPacket* rkpp = *buff;
    while(rkpp != 0)
    {
        rkpp = rkpp->next;
        n++;
    }
    return n;
}

void rkpPacket_sendl(struct rkpPacket** rkppl)
{
    while(*rkppl != 0)
        rkpPacket_send(rkpPacket_pop_begin(rkppl));
}
void rkpPacket_deletel(struct rkpPacket** rkppl)
{
    while(*rkppl != 0)
        rkpPacket_delete(rkpPacket_pop_begin(rkppl));
}
void rkpPacket_dropl(struct rkpPacket** rkppl)
{
    while(*rkppl != 0)
        rkpPacket_drop(rkpPacket_pop_begin(rkppl));
}
