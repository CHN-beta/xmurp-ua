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
    u_int32_t seq_ack;     // 下一个服务端确认收到的字节的序列号。以后所有的序列号都是以这个为基准的相对序列号。
    u_int32_t seq;         // 下一个期待收到的序列号。
    time_t last_active;
    u_int8_t scan_matched;
    u_int8_t win_preserve;
    struct rkpStream* next;
};

struct rkpStream* rkpStream_new(struct sk_buff*);                   // 构造函数，得到的流的状态是捕获这个数据包之前的状态。内存不够时返回 0。
void rkpStream_del(struct rkpStream*);                              // 析构函数
u_int8_t rkpStream_belong(struct rkpStream*, struct sk_buff*);      // 判断一个数据包是否属于一个流
u_int8_t rkpStream_execute(struct rkpStream*, struct sk_buff*);     // 处理一个数据包（假定包属于这个流）

void __rkpStream_refresh_ack(struct rkpStream*, u_int32_t);         // 刷新确认序列号。第二个参数就是即将设定的确认号。会自动重新计算序列号的偏移，以及释放 buff_prev 中的多余数据包

unsigned char* __rkpStream_skb_appStart(struct sk_buff*);                    // 返回一个包的应用层数据起始位置
u_int16_t __rkpStream_skb_appLen(struct sk_buff*);                  // 返回一个包的应用层数据长度
int32_t __rkpStream_skb_seq(u_int32_t, u_int32_t);                  // 返回一个序列号的相对序列号。两个参数分别为流的确认号、包的序列号（已经转换字节序）。

void __rkpStream_skb_send(struct sk_buff*);                         // 发送一个数据包
struct sk_buff* __rkpStream_skb_copy(struct sk_buff*);              // 复制一个数据包
void __rkpStream_skb_del(struct sk_buff*);                          // 删除一个数据包

u_int16_t __rkpStream_data_scan(unsigned char*, u_int16_t, unsigned char*, u_int8_t); // 在指定字符串中扫描子字符串。返回值最低位表示是否完整地找到，其余 15 位表示匹配的长度（如果没有完整地找到）或子串结束时相对于起始时的位置

void __rkpStream_buff_retain_end(struct sk_buff**, struct sk_buff*);        // 将一个数据包置入数据包链的末尾
void __rkpStream_buff_retain_auto(struct sk_buff**, struct sk_buff*);       // 将一个数据包置入数据包链的合适位置
void __rkpStream_buff_rejudge(struct rkpStream*, struct sk_buff**);         // 重新判定数据包链中的每个数据包
void __rkpStream_buff_del(struct sk_buff**);                                // 删除数据包链
struct sk_buff* __rkpStream_buff_find(struct sk_buff*, u_int32_t);
// 在一个已经按照序列号排序的数据包链中寻找序列号相符的包。如果没有相符的包，就返回最后一个序列号比要求的小的包。如果没有这样的包，就返回 0。第二个参数是要查找的序列号（绝对值，已转换字节序）

void __rkpStream_buff_execute_core(struct sk_buff**, u_int16_t);        // 最核心的步骤。集齐头部后，搜索、替换。

struct rkpStream* rpStream_new(struct sk_buff* skb)
{
    struct rkpStream* rkps = kmalloc(sizeof(struct rkpStream), GFP_KERNEL);
    struct iphdr* iph = ip_hdr(skb);
    struct tcphdr* tcph = tcp_hdr(skb);

    if(rkps == 0)
        return rkps;
    rkps -> status = rkpStream::__rkpStream_sniffing;
    rkps -> id[0] = ntohl(iph -> saddr);
    rkps -> id[1] = ntohl(iph -> daddr);
    rkps -> id[2] = (((u_int32_t)ntohs(tcph -> sport)) << 16 ) + ntohs(tcph -> dport);
    rkps -> buff = rkps -> buff_prev = rkps -> buff_next = 0;
    rkps -> seq_ack = ntohl(tcph -> seq);
    rkps -> seq = 1;
    rkps -> last_active = now();
    rkps -> scan_matched = 0;
    rkps -> win_preserve = rkpSettings_winPreserve(skb);
    rkps -> next = 0;
    return rkps;
}
void rkpStream_del(struct rkpStream* rkps)
{
    __rkpStream_buff_del(&(rkps -> buff));
    __rkpStream_buff_del(&(rkps -> buff_prev));
    __rkpStream_buff_del(&(rkps -> buff_next));
    kfree(rkps);
}
u_int8_t rkpStream_belong(struct rkpStream* rkps, struct sk_buff* skb)
{
    if(rkpSettings_request(skb))
    {
        if(rkps -> id[0] != ntohl(ip_hdr(skb) -> saddr))
            return 0;
        if(rkps -> id[1] != ntohl(ip_hdr(skb) -> daddr))
            return 0;
        if(rkps -> id[2] != ntohs(tcp_hdr(skb) -> sport) << 16 + ntohs(tcp_hdr(skb) -> dport);
            return 0;
        return 1;
    }
    else
    {
        if(rkps -> id[0] != ntohl(ip_hdr(skb) -> daddr))
            return 0;
        if(rkps -> id[1] != ntohl(ip_hdr(skb) -> saddr))
            return 0;
        if(rkps -> id[2] != ntohs(tcp_hdr(skb) -> dport) << 16 + ntohs(tcp_hdr(skb) -> sport);
            return 0;
        return 1;
    }
}
u_int8_t rkpStream_execute(struct rkpStream* rkps, struct sk_buff* skb)
// 不要害怕麻烦，咱们把每一种情况都慢慢写一遍。
{
    int32_t seq;

    // 肯定需要更新时间
    rkps -> last_active = now();

    // 服务端返回确认包的情况，更新一下确认号，返回 sccept。以后的情况，都是客户端发往服务端的了。
    if(!rkpSettings_request(skb))
    {
        int32_t seq = __rkpStream_skb_seq(rkps -> seq_ack, ntohl(tcp_hdr(skb) -> ack_seq));
        if(seq > 0)
        char    __rkpStream_refresh_ack(rkps, ntohl(tcp_hdr(skb) -> ack_seq));
        return NF_ACCEPT;
    }

    // 不携带应用层数据的情况。直接接受即可。以后的情况，都是含有应用层数据的包了。
    if(__rkpStream_skb_appLen(skb) == 0)
        return NF_ACCEPT;
    

    // 检查数据包是否是将来的数据包。如果是的话，需要放到 buff_next 等待处理。
    seq = __rkpStream_skb_seq(rkps -> seq_ack, ntohl(tcp_hdr(skb) -> seq));
    if(seq > rkps -> seq)
    {
        __rkpStream_buff_retain_auto(rkps -> buff_next, skb);
        return NF_STOLEN;
    }

    // 检查数据包是否是已经被确认的数据包。应该不会出现这种情况。出现的话就把它丢掉吧。
    if(seq < 0)
    {
        printk("rkp-ua::rkpStream: Re-transmission of asked package. Drop it.\n");
        return NF_DROP;
    }

    // 检查数据包是否是重传数据包。如果是的话，可能需要修改数据。然后，将它发出。接下来的情况，就一定是刚好是需要的序列号的情况了
    if(seq < rkps -> seq)
    {
        struct sk_buff* skb_prev = __rkpStream_buff_find(rkps -> buff_prev, ntohl(skb -> seq));
        if(skb_prev != 0 && tcp_hdr(skb_prev) -> seq == tcp_hdr(skb) -> seq)
        // 存在相符的数据包。将数据拷贝过去。
        {
            if(skb_ensure_writable(skb, __rkpStream_skb_appStart(skb) - skb -> data + __rkpStream_skb_appLen(skb)))
            {
                printk("rkp-ua::rkpStream::rkpStream_execute: Can not make skb writable, may caused by leasing memory. Drop it.\n");
                return NF_DROP;
            }
            memcpy(__rkpStream_skb_appStart(skb), __rkpStream_skb_appStart(skb_prev), __rkpStream_skb_appLen(skb_prev));
        }
        return NF_ACCEPT;
    }

    // 如果是在 sniffing 的情况下，那一定先扫描一下再说
    if(rkps -> status == __rkpStream_sniffing)
    {
        u_int16_t scan = __rkpStream_data_scan(__rkpStream_skb_appStart(skb), __rkpStream_skb_appLen(skb),
                str_end, rkps -> scan_matched);
        
        if(scan & 0x1)
        // 扫描找到了 HTTP 头的结尾，那么将这个数据包补到 buff 中，更新 seq，开始查找、替换、发出，然后根据情况设置状态，再考虑 buff_next 中的包，最后返回 STOLEN
        {
            struct sk_buff* skbp = rkps -> buff;

            // 追加到 buff 后面
            __rkpStream_buff_retain_end(&(rkps -> buff), skb);
            rkps -> seq = __rkpStream_skb_seq(rkps -> ack_seq, ntohl(tcp_hdr(skb) -> seq)) + __rkpStream_skb_appLen(skb);

            // 查找、替换
            __rkpStream_buff_execute_core(&(rkps -> buff), scan >> 1);

            // 循环复制一份到 buff_prev 下面，同时发出
            while(skbp != 0)
            {
                struct sk_buff* skbp2 = skbp -> next;
                __rkpStream_buff_retain_end(rkps -> buff_prev, __rkpStream_skb_copy(skbp));
                __rkpStream_skb_send(skbp);
                skbp = skbp2;
            }

            // 清空查找情况，重新设置状态
            rkps -> scan_length = 0;
            if(!(tcp_hdr(skb) -> psh))
                rkps -> status = waiting;

            // 考虑之前截留的数据包
            __rkpStream_buff_rejudge(rkps, &(skps -> buff_prev));

            return NF_STOLEN;
        }
        else if(tcp_hdr(skb) -> psh)
        // 如果没有找到却读到了 PUSH，这就比较迷了。打印一句警告，更新 seq，然后把截留的包都放行，然后考虑 buff_prev 里的数据。
        {
            struct sk_buff* skbp = rkps -> buff;

            // 打印警告
            printk("rkp-ua::rkpStream::rkpStream_execute: Find PSH before header ending found. Send without modification.\n");

            // 更新 seq
            rkps -> seq = __rkpStream_skb_seq(rkps -> ack_seq, ntohl(tcp_hdr(skb) -> seq)) + __rkpStream_skb_appLen(skb);

            // 放行截留的包
            while(skbp != 0)
            {
                struct sk_buff* skbp2 = skbp -> next;
                __rkpStream_skb_send(skbp);
                skbp = skbp2;
            }

            // 清空查找情况
            rkps -> scan_length = 0;

            // 考虑之前截留的数据包
            __rkpStream_buff_rejudge(rkps, &(skps -> buff_prev));

            return NF_ACCEPT;
        }
        else
        // 没有找到结尾，也没有push。那么，将这个数据包补到 buff 中，更新 seq 和 查找状态，再考虑 buff_next 中的包，最后返回 STOLEN
        {
            // 追加到 buff
            __rkpStream_buff_retain_end(rkps -> buff, skb);

            // 更新 seq 和查找状态
            rkps -> seq = __rkpStream_skb_seq(rkps -> ack_seq, ntohl(tcp_hdr(skb) -> seq)) + __rkpStream_skb_appLen(skb);
            rkps -> matched_length = scan >> 1;

            // 考虑 buff_next 中的包
            __rkpStream_buff_rejudge(rkps, &(skps -> buff_prev));

            return NF_STOLEN;
        }
    }
    else
    // 如果是在 waiting 的状态下，那么设置 seq 和状态，然后考虑 buff_next 中的包，然后返回 ACCEPT 就可以了
    {
        // 设置 seq 和状态
        rkps -> seq = __rkpStream_skb_seq(rkps -> ack_seq, ntohl(tcp_hdr(skb) -> seq)) + __rkpStream_skb_appLen(skb);
        if(tcp_hdr(skb) -> psh)
            rkps -> status = sniffing;
        
        // 考虑 buff_next
        __rkpStream_buff_rejudge(rkps, &(skps -> buff_prev));

        return NF_ACCEPT;
    }
}

void __rkpStream_refresh_ack(struct rkpStream* rkps, u_int32_t ack)
{
    struct sk_buff* skbp;

    // 重新计算 seq 偏移
    rkps -> seq -= ack - rkps -> seq_ack;

    // 丢弃 buff_prev 中已经确认收到的数据包
    skbp = rkps -> buff_prev;
    while(skbp != 0)
}

u_int16_t __rkpStream_dataLen(strct sk_buff* skb)
{
    return ntohs(ip_hdr(skb) -> tot_len) - ip_hdr(skb) -> ihl * 4 - tcp_hdr(skb) -> doff * 4;
}
