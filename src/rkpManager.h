#include "rkpStream.h"

struct rkpManager
{
    struct rkpStream** data;        // 按照首包的两端口之和的低 8 位放置
};

struct rkpManager* rkpManager_new(void);                    // 构造函数
void rkpManager_del(struct rkpManager*);                // 析构函数

u_int8_t rkpManager_execute(struct rkpManager*, struct sk_buff*);           // 处理一个数据包。返回值为 rkpStream_execute 的返回值。
void rkpManager_refresh(struct rkpManager*);                              // 清理过时的流

struct rkpManager* rkpManager_new(void)
{
    struct rkpManager* rkpm = kmalloc(sizeof(struct rkpManager) + sizeof(struct rkpStream*) * 256, GFP_KERNEL);
    if(rkpm == 0)
    {
        printk("rkp-ua::rkpManager::rkpStream_new: `kmalloc` failed, may caused by shortage of memory.\n");
        return 0;
    }
    rkpm -> data = (void*)rkpm + sizeof(struct rkpManager);
    memset(rkpm -> data, 0, sizeof(struct rkpStream*) * 256);
    return rkpm;
}
void rkpManager_del(struct rkpManager* rkpm)
{
    unsigned i;
    for(i = 0; i < 256; i++)
    {
        struct rkpStream *rkps = rkpm -> data[i];
        while(rkps != 0)
        {
            struct rkpStream *rkps2 = rkps -> next;
            rkpStream_del(rkps);
            rkps = rkps2;
        }
    }
    kfree(rkpm);
}

u_int8_t rkpManager_execute(struct rkpManager* rkpm, struct sk_buff* skb)
{
    if(rkpSettings_first(skb))
    // 新增加一个流或覆盖已经有的流
    {
        u_int8_t id = (ntohs(tcp_hdr(skb) -> source) + ntohs(tcp_hdr(skb) -> dest)) & 0xFF;
        struct rkpStream* rkps_new = rkpStream_new(skb);
        struct rkpStream *rkps = rkpm -> data[id];
        if(rkps_new == 0)
        {
            printk("rkp-ua::rkpStream::rkpStream_new: `kmalloc` failed, may caused by shortage of memory.\n");
            return NF_DROP;
        }

        // 查找可能的重复的流并删除
        while(rkps != 0)
            if(rkpStream_belong(rkps, skb))
            {
                if(rkps -> prev != 0)
                    rkps -> prev -> next = rkps -> next;
                if(rkps -> next != 0)
                    rkps -> next -> prev = rkps -> prev;
                if(rkps == rkpm -> data[id])
                    rkpm -> data[id] = rkps -> next;
                rkpStream_del(rkps);
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

        // 执行
        return rkpStream_execute(rkps_new, skb);
    }
    else
    // 使用已经有的流
    {
        u_int8_t id = (ntohs(tcp_hdr(skb) -> source) + ntohs(tcp_hdr(skb) -> dest)) & 0xFF;
        struct rkpStream *rkps = rkpm -> data[id];
        while(rkps != 0)
            if(rkpStream_belong(rkps, skb))
                return rkpStream_execute(rkps, skb);
            else
                rkps = rkps -> next;
        if(rkps == 0)
        {
            printk("rkp-ua::rkpStream::rkpStream_execute: Target stream not found.\n");
            return NF_DROP;
        }
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
                rkpStream_del(rkps);
                rkps = rkps2;
            }
            else
                rkps = rkps -> next;
    }
}