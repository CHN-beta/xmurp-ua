#pragma once
#include "rkpStream.h"

struct rkpManager
{
    struct rkpStream* data[256];        // 按照首包的两端口之和的低 8 位放置
    spinlock_t lock;                    // 线程锁
    struct timer_list timer;            // 定时器，用来定时清理不需要的流
};

struct rkpManager* rkpManager_new(void);
void rkpManager_delete(struct rkpManager*);

int rkpManager_execute(struct rkpManager*, struct sk_buff*);   // 处理一个数据包。返回值为 rkpStream_execute 的返回值。
int __rkpManager_execute(struct rkpManager*, struct sk_buff*);
void __rkpManager_refresh(unsigned long);  // 清理过时的流

void __rkpManager_lock(struct rkpManager*, unsigned long*);
void __rkpManager_unlock(struct rkpManager*, unsigned long);

struct rkpManager* rkpManager_new(void)
{
    struct rkpManager* rkpm = rkpMalloc(sizeof(struct rkpManager));
    if(rkpm == 0)
        return 0;
    memset(rkpm -> data, 0, sizeof(struct rkpStream*) * 256);
    // 初始化线程锁
    spin_lock_init(&rkpm -> lock);
    // 注册定时器
    init_timer(&rkpm -> timer);
    rkpm -> timer.function = __rkpManager_refresh;
    rkpm -> timer.data = (unsigned long)rkpm;
    rkpm -> timer.expires = jiffies + 600 * HZ;
    add_timer(&rkpm -> timer);
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
    del_timer(&rkpm -> timer);
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

    // 不使用标志位（三次握手）来判断是否该新建一个流，而直接搜索是否有符合条件的流，有就使用，没有就新建
    u_int8_t id = (ntohs(tcp_hdr(skb) -> source) + ntohs(tcp_hdr(skb) -> dest)) & 0xFF;
    struct rkpStream *rkps, *rkps_new;

    for(rkps = rkpm -> data[id]; rkps != 0; rkps = rkps -> next)
        if(rkpStream_belongTo(rkps, skb))
        {
#ifdef RKP_DEBUG
            printk("__rkpManager_execute: found target stream.\n");
#endif
            return rkpStream_execute(rkps, skb);
        }

    // 如果运行到这里的话，那就是没有找到了
#ifdef RKP_DEBUG
    printk("__rkpManager_execute: target stream not found, create a new one. \n");
#endif
    rkps_new = rkpStream_new(skb);
    if(rkps_new == 0)
        return NF_ACCEPT;
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
    return rkpStream_execute(rkps_new, skb);
}

void __rkpManager_refresh(unsigned long param)
{
    unsigned i;
    unsigned long flag;
    struct rkpManager* rkpm = (struct rkpManager*)param;
#ifdef RKP_DEBUG
    printk("__rkpManager_refresh start.\n");
#endif
    __rkpManager_lock(rkpm, &flag);
    for(i = 0; i < 256; i++)
    {
        struct rkpStream* rkps = rkpm -> data[i];
        while(rkps != 0)
            if(!rkps -> active)
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
            {
                rkps -> active = false;
                rkps = rkps -> next;
            }
    }
    __rkpManager_unlock(rkpm, flag);
#ifdef RKP_DEBUG
    printk("__rkpManager_refresh end.\n");
#endif
}

void __rkpManager_lock(struct rkpManager* rkpm, unsigned long* flagp)
{
    spin_lock_irqsave(&rkpm -> lock, *flagp);
}
void __rkpManager_unlock(struct rkpManager* rkpm, unsigned long flag)
{
    spin_unlock_irqrestore(&rkpm -> lock, flag);
}