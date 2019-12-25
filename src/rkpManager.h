#pragma once
#include "rkpStream.h"

struct rkpManager
{
    struct rkpStream* data[256];        // 按照首包的两端口之和的低 8 位放置
    time_t last_active;
    spinlock_t lock;         // 线程锁
};

struct rkpManager* rkpManager_new(void);
void rkpManager_delete(struct rkpManager*);

int rkpManager_execute(struct rkpManager*, struct sk_buff*);   // 处理一个数据包。返回值为 rkpStream_execute 的返回值。
int __rkpManager_execute(struct rkpManager*, struct sk_buff*);
void rkpManager_refresh(struct rkpManager*);  // 清理过时的流

void __rkpManager_lock(struct rkpManager*, unsigned long*);
void __rkpManager_unlock(struct rkpManager*, unsigned long);

struct rkpManager* rkpManager_new(void)
{
    struct rkpManager* rkpm = rkpMalloc(sizeof(struct rkpManager));
    if(rkpm == 0)
        return 0;
    memset(rkpm -> data, 0, sizeof(struct rkpStream*) * 256);
    spin_lock_init(&rkpm -> lock);
    return rkpm;
}
void rkpManager_delete(struct rkpManager* rkpm)
{
    unsigned i;
    unsigned long flag;
    __rkpManager_lock(rkpm, &flag);
    for(i = 0; i < 256; i++)
    {
        struct rkpStream* rkps = rkpm -> data[i];
        while(rkps != 0)
        {
            struct rkpStream *rkps2 = rkps -> next;
            rkpStream_delete(rkps);
            rkps = rkps2;
        }
    }
    __rkpManager_unlock(rkpm, flag);
    rkpFree(rkpm);
}

int rkpManager_execute(struct rkpManager* rkpm, struct sk_buff* skb)
{
    unsigned long flag;
    int rtn;
    __rkpManager_lock(rkpm, &flag);
    rtn = __rkpManager_execute(rkpm, skb);
    __rkpManager_unlock(rkpm, flag);
    return rtn;
}
int __rkpManager_execute(struct rkpManager* rkpm, struct sk_buff* skb)
{
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpManager_execute start.\n");
    printk("\tsyn %d ack %d\n", tcp_hdr(skb) -> syn, tcp_hdr(skb) -> ack);
    printk("\tsport %d dport %d\n", ntohs(tcp_hdr(skb) -> source), ntohs(tcp_hdr(skb) -> dest));
    printk("\tid %d\n", (ntohs(tcp_hdr(skb) -> source) + ntohs(tcp_hdr(skb) -> dest)) & 0xFF);
#endif
    rkpm -> last_active = now();
    if(rkpSettings_first(skb))
    // 新增加一个流或覆盖已经有的流
    {
        u_int8_t id = (ntohs(tcp_hdr(skb) -> source) + ntohs(tcp_hdr(skb) -> dest)) & 0xFF;
        struct rkpStream* rkps_new = rkpStream_new(skb);
        struct rkpStream* rkps = rkpm -> data[id];
#ifdef RKP_DEBUG
        printk("\nAdd a stream id=%u.\n", id);
#endif
        if(rkps_new == 0)
            return NF_ACCEPT;

        // 查找可能的重复的流并删除
        while(rkps != 0)
            if(rkpStream_belongTo(rkps, skb))
            {
                printk("Found same stream %u.\n", id);
                if(rkps -> prev != 0)
                    rkps -> prev -> next = rkps -> next;
                if(rkps -> next != 0)
                    rkps -> next -> prev = rkps -> prev;
                if(rkps == rkpm -> data[id])
                    rkpm -> data[id] = rkps -> next;
                rkpStream_delete(rkps);
                rkps = rkpm -> data[id];
                break;
            }
            else
                rkps = rkps -> next;

        // 插入新的流
        if(rkpm -> data[id] == 0)
        {
            rkpm -> data[id] = rkps_new;
#ifdef RKP_DEBUG
            printk("rkpManager_execute: add a new stream %d to an empty list.\n", id);
#endif
        }
        else
        {
            rkpm -> data[id] -> prev = rkps_new;
            rkps_new -> next = rkpm -> data[id];
            rkpm -> data[id] = rkps_new;
#ifdef RKP_DEBUG
            printk("rkpManager_execute: add a new stream %d to an unempty list.\n", id);
#endif
        }

        return NF_ACCEPT;
    }
    else
    // 使用已经有的流
    {
        u_int8_t id = (ntohs(tcp_hdr(skb) -> source) + ntohs(tcp_hdr(skb) -> dest)) & 0xFF;
        struct rkpStream* rkps = rkpm -> data[id];
#ifdef RKP_DEBUG
        printk("rkpStream_execute id %d\n", id);
#endif
        while(rkps != 0)
            if(rkpStream_belongTo(rkps, skb))
            {
#ifdef RKP_DEBUG
                printk("rkp-ua::rkpStream::rkpStream_execute: Target stream %u found.\n", id);
#endif
                return rkpStream_execute(rkps, skb);
            }
            else
                rkps = rkps -> next;
        printk("rkp-ua::rkpStream::rkpStream_execute: Target stream %u not found.\n", id);
        return NF_DROP;
    }
}

void rkpManager_refresh(struct rkpManager* rkpm)
{
    time_t n = now();
    unsigned i;
    unsigned long flag;
    __rkpManager_lock(rkpm, &flag);
    for(i = 0; i < 256; i++)
    {
        struct rkpStream* rkps = rkpm -> data[i];
        while(rkps != 0)
            if(rkps -> last_active + time_keepalive < n)
            {
                struct rkpStream *rkps2 = rkps -> next;
                if(rkps -> prev != 0)
                    rkps -> prev -> next = rkps -> next;
                if(rkps -> next != 0)
                    rkps -> next -> prev = rkps -> prev;
                if(rkps == rkpm -> data[i])
                    rkpm -> data[i] = rkps -> next;
                rkpStream_delete(rkps);
                rkps = rkps2;
            }
            else
                rkps = rkps -> next;
    }
    __rkpManager_unlock(rkpm, flag);
}

void __rkpManager_lock(struct rkpManager* rkpm, unsigned long* flagp)
{
    spin_lock_irqsave(&rkpm -> lock, *flagp);
}
void __rkpManager_unlock(struct rkpManager* rkpm, unsigned long flag)
{
    spin_unlock_irqrestore(&rkpm -> lock, flag);
}