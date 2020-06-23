#pragma once
#include "common.h"

struct rkpManager
{
    struct rkpStream* data[256];        // 按照两端口之和的低 8 位索引
    spinlock_t lock;                    // 线程锁
    struct timer_list timer;            // 定时器，用来定时清理不需要的流
};

struct rkpManager* rkpManager_new(void);
void rkpManager_delete(struct rkpManager*);

unsigned rkpManager_execute(struct rkpManager*, struct sk_buff*);   // 处理一个数据包。返回值为 rkpStream_execute 的返回值。
unsigned __rkpManager_execute(struct rkpManager*, struct rkpPacket*);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
void __rkpManager_refresh(unsigned long);                           // 清理长时间不活动的流，参数实际上是 rkpm 的地址
#else
void __rkpManager_refresh(struct timer_list*);
#endif

void __rkpManager_lock(struct rkpManager*, unsigned long*);
void __rkpManager_unlock(struct rkpManager*, unsigned long);

struct rkpManager* rkpManager_new(void)
{
    struct rkpManager* rkpm = (struct rkpManager*)rkpMalloc(sizeof(struct rkpManager));
    if(debug)
        printk("rkpManager_new\n");
    if(rkpm == 0)
        return 0;
    memset(rkpm -> data, 0, sizeof(struct rkpStream*) * 256);
    spin_lock_init(&rkpm -> lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
    init_timer(&rkpm -> timer);
    rkpm -> timer.function = __rkpManager_refresh;
    rkpm -> timer.data = (unsigned long)rkpm;
    rkpm -> timer.expires = jiffies + time_keepalive * HZ;
    add_timer(&rkpm -> timer);
#else
    rkpm -> timer.expires = jiffies + time_keepalive * HZ;
    timer_setup(&rkpm -> timer, __rkpManager_refresh, 0);
#endif
    return rkpm;
}
void rkpManager_delete(struct rkpManager* rkpm)
{
    unsigned i;
    unsigned long flag;
    if(debug)
        printk("rkpManager_delete\n");
    __rkpManager_lock(rkpm, &flag);
    del_timer(&rkpm -> timer);
    for(i = 0; i < 256; i++)
    {
        struct rkpStream* rkps = rkpm -> data[i];
        while(rkps != 0)
        {
            struct rkpStream* rkps2 = rkps -> next;
            rkpStream_delete(rkps);
            rkps = rkps2;
        }
    }
    __rkpManager_unlock(rkpm, flag);
    rkpFree(rkpm);
}

unsigned rkpManager_execute(struct rkpManager* rkpm, struct sk_buff* skb)
{
    unsigned long flag;
    unsigned rtn;
    struct rkpPacket* rkpp;
    if(debug)
        printk("rkpManager_execute\n");
    __rkpManager_lock(rkpm, &flag);
    rkpp = rkpPacket_new(skb, rkpSetting_ack(skb));
    rtn = __rkpManager_execute(rkpm, rkpp);
    if(debug)
    {
        if(rtn == NF_ACCEPT)
            printk("returned NF_ACCEPT.\n");
        else if(rtn == NF_DROP)
            printk("returned NF_DROP.\n");
        else if(rtn == NF_STOLEN)
            printk("returned NF_STOLEN.\n");
    }
    __rkpManager_unlock(rkpm, flag);
    if(rtn == NF_ACCEPT || rtn == NF_DROP)
        rkpPacket_delete(rkpp);
    return rtn;
}
unsigned __rkpManager_execute(struct rkpManager* rkpm, struct rkpPacket* rkpp)
{
    struct rkpStream *rkps, *rkps_new;

    // 搜索是否有符合条件的流
    for(rkps = rkpm -> data[rkpp -> sid]; rkps != 0; rkps = rkps -> next)
        if(rkpStream_belongTo(rkps, rkpp))       // 找到了，执行即可
            return rkpStream_execute(rkps, rkpp);

    // 如果运行到这里的话，那就是没有找到了，新建一个流再执行
    rkps_new = rkpStream_new(rkpp);
    if(rkps_new == 0)
        return NF_ACCEPT;
    if(rkpm -> data[rkpp -> sid] == 0)
        rkpm -> data[rkpp -> sid] = rkps_new;
    else
    {
        rkpm -> data[rkpp -> sid] -> prev = rkps_new;
        rkps_new -> next = rkpm -> data[rkpp -> sid];
        rkpm -> data[rkpp -> sid] = rkps_new;
    }
    return rkpStream_execute(rkps_new, rkpp);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
void __rkpManager_refresh(unsigned long param)
{
    struct rkpManager* rkpm = (struct rkpManager*)param;
#else
void __rkpManager_refresh(struct timer_list* timer)
{
    struct rkpManager* rkpm = from_timer(rkpm, timer, timer);
#endif

    unsigned i;
    unsigned long flag;

    if(debug)
        printk("rkpManager_refresh\n");
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
    rkpm -> timer.expires = jiffies + time_keepalive * HZ;
    add_timer(&rkpm -> timer);
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