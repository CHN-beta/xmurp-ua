#pragma once
#include "rkpStream.h"

struct rkpManager
{
    struct rkpStream* data[256];        // 按照首包的两端口之和的低 8 位放置
    time_t last_active;
    struct mutex* lock;         // 线程锁，这个需要外部静态地生成后，把指针传进来
};

struct rkpManager* rkpManager_new(struct mutex*);
void rkpManager_delete(struct rkpManager*);

u_int8_t rkpManager_execute(struct rkpManager*, struct sk_buff*);   // 处理一个数据包。返回值为 rkpStream_execute 的返回值。
void rkpManager_refresh(struct rkpManager*);  // 清理过时的流

void __rkpManager_lock(struct rkpManager*);
void __rkpManager_unlock(struct rkpManager*);

struct rkpManager* rkpManager_new(struct mutex* lock)
{
    struct rkpManager* rkpm = rkpMalloc(sizeof(struct rkpStream));
    if(rkpm == 0)
        return 0;
    memset(rkpm -> data, 0, sizeof(struct rkpStream*) * 256);
    rkpm -> lock = lock;
    mutex_init(rkpm -> lock);
    return rkpm;
}
void rkpManager_delete(struct rkpManager* rkpm)
{
    // __rkpManager_lock(rkpm);
    unsigned i;
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
    // __rkpManager_unlock(rkpm);
    rkpFree(rkpm);
}

u_int8_t rkpManager_execute(struct rkpManager* rkpm, struct sk_buff* skb)
{
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpManager_execute start.\n");
    printk("\tsyn %d ack %d\n", tcp_hdr(skb) -> syn, tcp_hdr(skb) -> ack);
    printk("\tsport %d dport %d\n", tcp_hdr(skb) -> source, tcp_hdr(skb) -> dest);
    printk("\tid %d\n", (ntohs(tcp_hdr(skb) -> source) + ntohs(tcp_hdr(skb) -> dest)) & 0xFF);
#endif
    __rkpManager_lock(rkpm);
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
            rkpm -> data[id] = rkps_new;
        else
        {
            rkpm -> data[id] -> prev = rkps_new;
            rkps_new -> next = rkpm -> data[id];
            rkpm -> data[id] = rkps_new;
        }

        return NF_ACCEPT;
    }
    else
    // 使用已经有的流
    {
        u_int8_t id = (ntohs(tcp_hdr(skb) -> source) + ntohs(tcp_hdr(skb) -> dest)) & 0xFF;
        struct rkpStream* rkps = rkpm -> data[id];
#ifdef RKP_DEBUG
        printk("rkpStream_belong %d\n", (int)rkpStream_belongTo(rkps, skb));
#endif
        while(rkps != 0)
            if(rkpStream_belongTo(rkps, skb))
                return rkpStream_execute(rkps, skb);
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
}

void __rkpManager_lock(struct rkpManager* rkpm)
{
    mutex_lock(rkpm -> lock);
}
void __rkpManager_unlock(struct rkpManager* rkpm)
{
    mutex_unlock(rkpm -> lock);
}