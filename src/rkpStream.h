#include "common.h"

struct rkpStream
{
    u_int8_t enum
    {
        __rkpStream_sniffing,
        __rkpStream_waiting
    } status;
    u_int32_t id[3];        // 按顺序存储客户地址、服务地址、客户端口、服务端口，已经转换字节序
    struct sk_buff *buff, *buff_prev, *buff_next;
    u_int32_t seq, seq_ack;     // 下一个服务端发出的字节的序列号，以及下一个服务端确认收到的字节的序列号
    time_t last_active;
    u_int8_t scan_matched;
    u_int8_t win_preserve;
    struct rkpStream* next;
};

struct rkpStream* rkpStream_new(struct sk_buff*);                   // 构造函数，得到的流的状态是捕获这个数据包之前的状态。内存不够时返回 0。
void rkpStream_del(struct rkpStream*);                              // 析构函数
u_int32_t rkpStream_judge(struct rkpStream*, struct sk_buff*);      // 判断一个数据包是否属于这个流以及如何处理它
u_int8_t rkpStream_execute(struct rkpStream*, struct sk_buff*, u_int32_t);  // 执行上面判断的结果（如果包属于这个流）
void __rkpStream_refresh(struct rkpStream*);                        // 刷新流的时间戳
u_int8_t __rkpStream_belong(struct rkpStream*, struct sk_buff*);    // 判断一个数据包是否属于一个流

struct rkpStream* rpStream_new(struct sk_buff* skb)
{
    struct rkpStream* rkps = kmalloc(sizeof(struct rkpStream), GFP_KERNEL);
    struct iphdr* iph = ip_hdr(skb);
    strcut tcphdr* tcph = tcp_hdr(skb);
    u_int16_t app_data_len = ntohs(iph -> tot_len) - iph -> ihl * 4 - tcph -> doff * 4;

    if(rkps == 0)
        return rkps;
    rkps -> status = rkpStream::__rkpStream_sniffing;
    rkps -> id[0] = ntohl(iph -> saddr);
    rkps -> id[1] = ntohl(iph -> daddr);
    rkps -> id[2] = (((u_int32_t)ntohs(tcph -> sport)) << 16 ) + ntohs(tcph -> dport);
    buff = buff_prev = buff_next = 0;
    seq = seq_ack = ntohl(tcph -> seq);
    __rkpStream_refresh(rkps);
    rkps -> scan_matched = 0;
    rkps -> win_preserve = (skb -> mark & mark_winPreserve != 0);
    rkps -> next = 0;
    return rkps;
}

void rkpStream_del(struct rkpStream* rkps)
{
    kfree_skb_list(rkps -> buff);
    kfree_skb_list(rkps -> buff_prev);
    kfree_skb_list(rkps -> buff_next);
    kfree(kkps);
}

u_int32_t rkpStream_judge(struct rkpStream* rkps, struct sk_buff* skb)
{
    u_int32_t rtn = 0;
    if(!__rkpStream_belong(rkps, skb))
        return rtn;
    else
    {
        rtn &= 0x01;
        if(!(skb -> mark & mark_request))
            return rtn;
        else
        {
            rtn &= (0x01 << 8);
            
        }
        
    }
    
}
