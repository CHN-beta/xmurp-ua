#pragma once
#include "rkpSettings.h"
#include "rkpPacket.h"

struct rkpStream
// 接管一个 TCP 流。忽略重传（一律放行）。因此，也不需要捕获来自服务端的包。
{
    enum
    {
        __rkpStream_sniffing,
        __rkpStream_waiting
    } status;
    u_int32_t id[3];        // 按顺序存储客户地址、服务地址、客户端口、服务端口，已经转换字节序
    struct rkpPacket *buff_scan, *buff_disordered;      // 分别存储准备扫描的、因乱序而提前收到的数据包，都按照字节序排好了
    u_int32_t seq_offset;       // 序列号的偏移。使得 buff_scan 中第一个字节的编号为零。
    time_t last_active;         // 最后活动时间，用来剔除长时间不活动的流。
    unsigned scan_matched;      // 记录现在已经匹配了多少个字节
    struct rkpStream *prev, *next;
};

struct rkpStream* rkpStream_new(const struct sk_buff*);   // 由三次握手的第一个包构造一个 rkpSteam
void rkpStream_delete(struct rkpStream*);

bool rkpStream_belongTo(const struct rkpStream*, const struct sk_buff*);      // 判断一个数据包是否属于一个流
unsigned rkpStream_execute(struct rkpStream*, struct sk_buff*);     // 已知一个数据包属于这个流后，处理这个数据包

int32_t __rkpStream_seq_scanEnd(struct rkpStream*);         // 返回 buff_scan 中最后一个数据包的后继的第一个字节的序列号

void __rkpStream_insert_auto(struct rkpStream*, struct rkpPacket**, struct rkpPacket*);     // 在指定链表中插入一个节点
void __rkpStream_insert_end(struct rkpStream*, struct rkpPacket**, struct rkpPacket*);

bool __rkpStream_scan(struct rkpStream*, struct rkpPacket*, unsigned char*);  // 在包的应用层搜索 ua 头的结尾
void __rkpStream_modify(struct rkpStream*);         // 在已经收集到完整的 HTTP 头后，调用去按规则修改 buff_scan 中的包

void __rkpStream_skb_send(struct sk_buff*);                         // 发送一个数据包
struct sk_buff* __rkpStream_skb_copy(const struct sk_buff*);              // 复制一个数据包
void __rkpStream_skb_del(struct sk_buff*);                          // 删除一个数据包
void __rkpStream_skb_csum(struct sk_buff*);                         // 重新计算 tcp 和 ip 的校验和

u_int16_t __rkpStream_data_scan(const unsigned char*, u_int16_t, const unsigned char*, u_int8_t); // 在指定字符串中扫描子字符串。返回值最低位表示是否完整地找到，其余 15 位表示匹配的长度（如果没有完整地找到）或子串结束时相对于起始时的位置
void __rkpStream_data_replace(unsigned char*, u_int16_t, const unsigned char*, u_int16_t);   // 替换字符串。最后一个参数表明已经替换了多少个字节。其它参数与前者类似。

void __rkpStream_buff_retain_end(struct sk_buff**, struct sk_buff*);        // 将一个数据包置入数据包链的末尾
void __rkpStream_buff_retain_auto(struct sk_buff**, struct sk_buff*);       // 将一个数据包置入数据包链的合适位置
void __rkpStream_buff_rejudge(struct rkpStream*, struct sk_buff**);         // 重新判定数据包链中的每个数据包
struct sk_buff* __rkpStream_buff_find(const struct sk_buff*, u_int32_t);
// 在一个已经按照序列号排序的数据包链中寻找序列号相符的包。如果没有相符的包，就返回最后一个序列号比要求的小的包。如果没有这样的包，就返回 0。第二个参数是要查找的序列号（绝对值，已转换字节序）

void __rkpStream_buff_execute_core(struct sk_buff**, u_int16_t, bool);        // 最核心的步骤，集齐头部后被调用。搜索、替换。参数分别为：数据包链表、最后一个包中 http 头最后一个字节的位置、是否保留指定 ua

struct rkpStream* rkpStream_new(const struct sk_buff* skb)
{
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpStream_new start.\n");
#endif
    struct rkpStream* rkps = rkpMalloc(sizeof(struct rkpStream));
    const struct iphdr* iph = ip_hdr(skb);
    const struct tcphdr* tcph = tcp_hdr(skb);
    if(rkps == 0)
    {
        printk("rkp-ua: rkpStream_new: malloc failed, may caused by shortage of memory.\n");
        return 0;
    }
    rkps -> status = __rkpStream_sniffing;
    rkps -> id[0] = ntohl(iph -> saddr);
    rkps -> id[1] = ntohl(iph -> daddr);
    rkps -> id[2] = (((u_int32_t)ntohs(tcph -> source)) << 16) + ntohs(tcph -> dest);
    rkps -> buff_scan = rkps -> buff_disordered = rkps -> buff_sent = 0;
    rkps -> seq_offset = ntohl(skb -> seq) + 1;
    rkps -> last_active = now();
    rkps -> scan_matched = 0;
    rkps -> prev = rkps -> next = 0;
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpStream_new end.\n");
#endif
    return rkps;
}
void rkpStream_delete(struct rkpStream* rkps)
{
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpStream_delete start.\n");
#endif
    for(struct rkpPacket* p = rkps -> buff_scan; p != 0;)
    {
        struct rkpPacket* p2 = p;
        p = p -> next;
        rkpPacket_drop(p2);
    }
    for(struct rkpPacket* p = rkps -> buff_disordered; p != 0;)
    {
        struct rkpPacket* p2 = p;
        p = p -> next;
        rkpPacket_drop(p2);
    }
    for(struct rkpPacket* p = rkps -> buff_sent; p != 0;)
    {
        struct rkpPacket* p2 = p;
        p = p -> next;
        rkpPacket_delete(p2);
    }
    rkpFree(rkps);
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpStream_delete end.\n");
#endif
}

bool rkpStream_belong(const struct rkpStream* rkps, const struct sk_buff* skb)
{
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpStream_belongTo start.\n");
    printk("\tsyn %d ack %d\n", tcp_hdr(skb) -> syn, tcp_hdr(skb) -> ack);
    printk("\tsport %d dport %d\n", ntohs(tcp_hdr(skb) -> source), ntohs(tcp_hdr(skb) -> dest));
    printk("\tsip %u dip %u\n", ntohl(ip_hdr(skb) -> saddr), ntohl(ip_hdr(skb) -> daddr));
    printk("\trkpSettings_request %d\n", rkpSettings_request(skb));
    printk("\tid %u %u %u", rkps -> id[0], rkps -> id[1], rkps -> id[2]);
#endif
    bool rtn;
    if(rkpSettings_request(skb))
    {
        if(rkps -> id[0] != ntohl(ip_hdr(skb) -> saddr))
            rtn = false;
        if(rkps -> id[1] != ntohl(ip_hdr(skb) -> daddr))
            rtn = false;
        if(rkps -> id[2] != (((u_int32_t)ntohs(tcp_hdr(skb) -> source)) << 16) + ntohs(tcp_hdr(skb) -> dest))
            rtn = false;
        rtn = true;
    }
    else
    {
        if(rkps -> id[0] != ntohl(ip_hdr(skb) -> daddr))
            rtn = false;
        if(rkps -> id[1] != ntohl(ip_hdr(skb) -> saddr))
            rtn = false;
        if(rkps -> id[2] != (((u_int32_t)ntohs(tcp_hdr(skb) -> dest)) << 16) + ntohs(tcp_hdr(skb) -> source))
            rtn = false;
        rtn = true;
    }
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpStream_belongTo end, will return %d.\n", rtn);
#endif
    return rtn;
}
unsigned rkpStream_execute(struct rkpStream* rkps, struct sk_buff* skb)
// 不要害怕麻烦，咱们把每一种情况都慢慢写一遍。
{
    struct rkpPacket* p = rkpPacket_new(skb);
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpStream_execute start.\n");
#endif

    // 肯定需要更新时间
    rkps -> last_active = now();

    // 不携带应用层数据的情况。直接接受即可。以后的情况，都是含有应用层数据的包了。
    if(rkpPacket_appLen(p) == 0)
    {
#ifdef RKP_DEBUG
        printk("\tblank packet judged.\n");
#endif
        rkpPacket_delete(p);
        return NF_ACCEPT;
    }
    
    // 接下来从小到大考虑数据包的序列号的几种情况
    // 已经发出的数据包，直接忽略
    if(int32_t(rkpPacket_seq(p) - rkps -> seq_offset) < 0)
    {
#ifdef RKP_DEBUG
        printk("\tsent packet judged.\n");
#endif
        rkpPacket_delete(p);
        return NF_ACCEPT;
    }
    // 已经放到 buff_scan 中的数据包，丢弃
    if(int32_t(rkpPacket_seq(p) - rkps -> seq_offset) < __rkpStream_seq_scanEnd(rkps))
    {
#ifdef RKP_DEBUG
        printk("\tcaptured packet judged.\n");
#endif
        rkpPacket_delete(p);
        return NF_DROP;
    }
    // 恰好是 buff_scan 的后继数据包，这种情况比较麻烦，写到最后
    // 乱序导致还没接收到前继的数据包，放到 buff_disordered
    if(int32_t(rkpPacket_seq(p) - rkps -> seq_offset) > __rkpStream_seq_scanEnd(rkps))
    {
#ifdef RKP_DEBUG
        printk("\tdisordered packet judged.\n");
#endif
        __rkpStream_insert_auto(&(rkps -> buff_disordered), p);
        return NF_STOLEN;
    }

    // 接下来是恰好是 buff_scan 的后继数据包的情况，先分状态讨论，再一起考虑 buff_disordered 中的包
#ifdef RKP_DEBUG
        printk("\tdesired packet judged.\n");
#endif
    unsigned rtn;
    // 如果是在 sniffing 的情况下，那一定先丢到 buff_scan 里，然后扫描一下看结果，重新设定状态
    if(rkps -> status == __rkpStream_sniffing)
    {
#ifdef RKP_DEBUG
        printk("\t\tsniffing.\n");
#endif
        // 丢到 buff_scan 里
        __rkpStream_insert_end(rkps, &(rkps -> buff_scan), p);
        if(__rkpStream_scan(rkps, p, str_head_end))     // 扫描到了
        {
#ifdef RKP_DEBUG
            printk("\t\t\thttp head end matched.\n");
#endif
            // 替换 ua
            __rkpStream_modify(rkps);
            // 发出数据包，注意最后一个不发，等会儿 accept 就好
            for(struct rkpPacket* p = rkps -> buff_scan; p != 0 && p -> next != 0;)
            {
                struct rkpPacket* p2 = p;
                p = p -> next;
                rkps -> seq_offset = rkpPacket_seq(p2) + rkpPacket_appLen(p2);  // 别忘了更新偏移
                rkpPacket_send(p2);
            }
            rkps -> buff_scan = 0;
            // 设定状态为等待
            rkps -> status = __rkpStream_waiting;
            // accept
            rtn = NF_ACCEPT;
        }
        // 没有扫描到，那么 stolen
        else
        {
            if(rkpPacket_psh(p))    // 如果同时没有 psh，就偷走
                rtn = NF_STOLEN;
#ifdef RKP_DEBUG
            printk("\t\t\thttp head end not matched.\n");
#endif
        }
        // 处理一下 psh
        if(rkpPacket_psh(p))
        {
#ifdef RKP_DEBUG
            printk("\t\t\tpsh found.\n");
#endif
            if(rkps -> buff_scan != 0)      // 如果刚刚没有扫描到 http 结尾
            {
#ifdef RKP_DEBUG
                printk("rkp-ua: rkpStream_execute: psh found before http head end.\n");
#endif
                for(struct rkpPacket* p = rkps -> buff_scan; p != 0 && p -> next != 0;)
                {
                    struct rkpPacket* p2 = p;
                    p = p -> next;
                    rkps -> seq_offset = rkpPacket_seq(p2) + rkpPacket_appLen(p2);
                    rkpPacket_send(p2);
                }
            }
            else        // 如果刚刚扫描到了
                rkps -> status = __rkpStream_sniffing;

            // 只要有 psh，肯定接受
            rtn = NF_ACCEPT;
        }
    }
    else    // waiting 的状态，检查 psh、设置序列号偏移、然后放行就可以了
    {
#ifdef RKP_DEBUG
        printk("\t\tsniffing.\n");
#endif
        if(rkpPacket_psh(p))
            rkps -> status = __rkpStream_sniffing;
        rtn = NF_ACCEPT;
    }

    // 考虑 buff_disordered
    while(rkps -> buff_disordered != 0)
    {
        if(rkpPacket_seq(rkps -> buff_disordered) - rkps -> seq_offset < __rkpStream_seq_scanEnd(rkps))
        // 序列号是已经发出去的，丢弃
        {
            if(rkps -> buff_disordered -> next == 0)
            {
                rkpPacket_drop(rkps -> buff_disordered);
                rkps -> buff_disordered = 0;
            }
            else
            {
                rkps -> buff_disordered = rkps -> buff_disordered -> next;
                rkpPacket_drop(rkps -> buff_disordered -> prev);
                rkps -> buff_disordered -> prev = 0;
            }
        }
        // 如果序列号过大，结束循环
        else if(rkpPacket_seq(rkps -> buff_disordered) - rkps -> seq_offset > __rkpStream_seq_scanEnd(rkps))
            break;
        // 如果序列号恰好，把它从链表中取出，然后像刚刚抓到的包那样去执行
        else
        {
            // 将包从链表中取出
            struct rkpPacket* p2 = rkps -> buff_disordered;
            if(rkps -> buff_disordered -> next == 0)
                rkps -> buff_disordered = 0;
            else
            {
                rkps -> buff_disordered = rkps -> buff_disordered -> next;
                rkps -> buff_disordered -> prev = 0;
            }
            // 执行
            unsigned rtn = rkpStream_execute(rkps, p2 -> skb);
            if(rtn == NF_ACCEPT)
                rkpPacket_send(p2);
            else if(rtn == NF_DROP)
                rkpPacket_drop(p2);
            else if(rtn == NF_STOLEN)
                rkpPacket_delete(p2);
        }
    }
    
    return rtn;
    }
}

u_int16_t __rkpStream_data_scan(const unsigned char* data, u_int16_t data_len, const unsigned char* target, u_int8_t matched)
{
    const unsigned char* p = data;
    while(p - data != data_len)
    {
        if(*p == target[matched])
            matched++;
        else
            matched = 0;
        if(matched == strlen(target))
            return (((u_int16_t)(p - data) << 1)) | 0x1;
        else
            p++;
    }
    return matched << 1;
}
void __rkpStream_data_replace(unsigned char* data, u_int16_t data_len, const unsigned char* target, u_int16_t modified)
{
    while(modified < strlen(target) && data_len > 0)
    {
        *data = target[modified];
        data++;
        data_len--;
        modified++;
    }
    if(data_len > 0)
        memset(data, ' ', data_len);
}

void __rkpStream_buff_retain_end(struct sk_buff** buff, struct sk_buff* skb)
{
    struct sk_buff* p = *buff;
    if(p == 0)
    {
        *buff = skb;
        skb -> next = 0;
        skb -> prev = 0;
    }
    else
    {
        while(p -> next != 0)
            p = p -> next;
        p -> next = skb;
        skb -> next = 0;
        skb -> prev = p;
    }
}
void __rkpStream_buff_retain_auto(struct sk_buff** buff, struct sk_buff* skb)
{
    struct sk_buff* p = __rkpStream_buff_find(*buff, ntohl(tcp_hdr(skb) -> seq));
    if(p == 0)
    {
        skb -> prev = 0;
        skb -> next = *buff;
        *buff = skb;
        if(skb -> next != 0)
            skb -> next -> prev = skb;
    }
    else if(ntohl(tcp_hdr(p) -> seq) == ntohl(tcp_hdr(skb) -> seq))
    {
        if(p -> prev != 0)
            p -> prev -> next = skb;
        if(p -> next != 0)
            p -> next -> prev = skb;
        skb -> prev = p -> prev;
        skb -> next = p -> next;
        if(*buff == p)
            *buff = skb;
        __rkpStream_skb_del(p);
    }
    else
    {
        if(p -> next != 0)
            p -> next -> prev = skb;
        skb -> next = p -> next;
        p -> next = skb;
        skb -> prev = p;
    }
}

struct sk_buff* __rkpStream_buff_find(const struct sk_buff* skb, u_int32_t seq)
{
    if(skb == 0)
        return 0;
    else
    {
        while(skb -> next != 0 && __rkpStream_skb_seq(seq, ntohl(tcp_hdr(skb -> next) -> seq)) <= 0)
            skb = (const struct sk_buff*)skb -> next;
        return (struct sk_buff*)skb;
    }
}

void __rkpStream_buff_execute_core(struct sk_buff** buff, u_int16_t last_pos, bool preserve)
// 扫描是否有 ua，然后扫描 ua 中是否有匹配的字符串，并且进行修改
{
    u_int16_t rtn;
    struct sk_buff* p;
    unsigned i;

    struct sk_buff *skb_ua_begin, *skb_ua_end;
    u_int16_t pos_ua_begin, pos_ua_end;

#ifdef RKP_DEBUG
    printk("__rkpStream_buff_execute_core\n");
    printk("\tlast_pos %u\n", last_pos);
    printk("\tpreserve %d\n", preserve);
    printk("\tstart find ua start.\n");
#endif

    // 寻找 ua 开始的位置
    for(p = *buff, rtn = 0; p != 0; p = p -> next)
    {
#ifdef RKP_DEBUG
        printk("\tfind a packet.\n");
#endif
        if(p -> next == 0)
            rtn = __rkpStream_data_scan(__rkpStream_skb_appBegin(p), last_pos + 1, str_ua_begin, rtn >> 1);
        else
            rtn = __rkpStream_data_scan(__rkpStream_skb_appBegin(p), __rkpStream_skb_appLen(p), str_ua_begin, rtn >> 1);
        if(rtn & 0x1)
            break;
    }
    if(rtn & 0x1)
    // 找到了
    {
#ifdef RKP_DEBUG
        printk("\tfound.\n");
#endif
        skb_ua_begin = p;
        pos_ua_begin = (rtn >> 1) + 1;
    }
    else
    // 没找到
    {
#ifdef RKP_DEBUG
        printk("\tfound.\n");
#endif
        return;
    }

    // 寻找 ua 结束的位置
    for(rtn = 0; p != 0; p = p -> next)
    {
        if(p == skb_ua_begin)
        {
            rtn = __rkpStream_data_scan(__rkpStream_skb_appBegin(p) + pos_ua_begin, __rkpStream_skb_appLen(p) - pos_ua_begin, str_ua_end, rtn >> 1);
            // 这时得到的 rtn 是相对于扫描开始处的位置，因此如果确认扫描到了结尾，就需要再加上相对于应用层开始处的偏移
            if(rtn & 0x01)
                rtn += pos_ua_begin << 1;
        }
        else
            rtn = __rkpStream_data_scan(__rkpStream_skb_appBegin(p), __rkpStream_skb_appLen(p), str_ua_end, rtn >> 1);
        if(rtn & 0x1)
            break;
    }
    if(!(rtn & 0x01))
    {
        printk("rkp-ua::rkpStream::__rkpStream_buff_execute_core: UA end not found. Accept without modification.\n");
        return;
    }
    // 肯定是可以找到结束位置的。
    // 如果找到的结束位置在靠近应用层数据开头的位置，那么真实的结束位置应该在上一个数据包
    if((rtn >> 1) < strlen(str_ua_end))
    {
        skb_ua_end = p -> prev;
        pos_ua_end = __rkpStream_skb_appLen(skb_ua_end) - (strlen(str_ua_end) - (rtn >> 1) - 1) - 1;
    }
    else
    {
        skb_ua_end = p;
        pos_ua_end = (rtn >> 1) - strlen(str_ua_end);
    }

    // 检查 ua 是否需要忽略，如果需要忽略就忽略
    if(preserve)
        for(i = 0; i < n_str_preserve; i++)
        {
            for(p = skb_ua_begin, rtn = 0;;p = p -> next)
            {
                const unsigned char* scan_begin;
                u_int16_t scan_len;
                if(p == skb_ua_begin)
                    scan_begin = __rkpStream_skb_appBegin(p) + pos_ua_begin;
                else
                    scan_begin = __rkpStream_skb_appBegin(p);
                if(p == skb_ua_end)
                    scan_len = (__rkpStream_skb_appBegin(p) + pos_ua_end) - scan_begin + 1;
                else
                    scan_len = (__rkpStream_skb_appBegin(p) + __rkpStream_skb_appLen(p) - 1) - scan_begin + 1;
                rtn = __rkpStream_data_scan(scan_begin, scan_len, str_preserve[i], rtn >> 1);
                if(rtn & 0x1)
                    return;
                if(p == skb_ua_end)
                    break;
            }
        }

#ifdef RKP_DEBUG
    printk("\tstr_ua_rkp %s\n", str_ua_rkp);
    printk("\tskb_ua_end - skb_ua_begin %d\n", skb_ua_end - skb_ua_begin);
    printk("\tpos_ua_end %d pos_ua_begin %d\n", pos_ua_end, pos_ua_begin);
    // return;
#endif
    
    // 替换 ua
    for(p = skb_ua_begin, rtn = 0;;p = p -> next)
    {
        unsigned char* replace_begin;
        u_int16_t replace_len;
        if(skb_ensure_writable(p, __rkpStream_skb_appBegin(p) + __rkpStream_skb_appLen(p) - p -> data) != 0)
        {
            printk("rkp-ua::rkpStream::__rkpStream_buff_execute_core: Can not make skb writable, may caused by shortage of memory. Ignore it.\n");
            return;
        }
        if(p == skb_ua_begin)
            replace_begin = __rkpStream_skb_appBegin(p) + pos_ua_begin;
        else
            replace_begin = __rkpStream_skb_appBegin(p);
        if(p == skb_ua_end)
            replace_len = (__rkpStream_skb_appBegin(p) + pos_ua_end) - replace_begin + 1;
        else
            replace_len = (__rkpStream_skb_appBegin(p) + __rkpStream_skb_appLen(p) - 1) - replace_begin + 1;
#ifdef RKP_DEBUG
    printk("\treplace_begin - appBegin %d\n", replace_begin - __rkpStream_skb_appBegin(p));
    printk("\treplace_len %d\n", replace_len);
#endif
        __rkpStream_data_replace(replace_begin, replace_len, str_ua_rkp, rtn);
#ifdef RKP_DEBUG
    printk("\tafter replace, data is %c%c%c%c%c\n", replace_begin[0], replace_begin[1], replace_begin[2], replace_begin[3], replace_begin[4]);
#endif
        __rkpStream_skb_csum(p);
        rtn += replace_len;
        if(p == skb_ua_end)
            break;
    }
}