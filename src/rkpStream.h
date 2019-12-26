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
struct rkpPacket* __rkpStream_pop_end(struct rkpStream*, struct rkpPacket**);

bool __rkpStream_scan(struct rkpStream*, struct rkpPacket*);  // 在包的应用层搜索 ua 头的结尾
void __rkpStream_modify(struct rkpStream*);         // 在已经收集到完整的 HTTP 头后，调用去按规则修改 buff_scan 中的包

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
    rkps -> buff_scan = rkps -> buff_disordered = 0;
    rkps -> seq_offset = ntohl(tcp_hdr(skb) -> seq) + 1;
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
    struct rkpPacket* p;
    for(p = rkps -> buff_scan; p != 0;)
    {
        struct rkpPacket* p2 = p;
        p = p -> next;
        rkpPacket_drop(p2);
    }
    for(p = rkps -> buff_disordered; p != 0;)
    {
        struct rkpPacket* p2 = p;
        p = p -> next;
        rkpPacket_drop(p2);
    }
    rkpFree(rkps);
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpStream_delete end.\n");
#endif
}

bool rkpStream_belongTo(const struct rkpStream* rkps, const struct sk_buff* skb)
{
#ifdef RKP_DEBUG
    printk("rkp-ua: rkpStream_belongTo start.\n");
    printk("\tsyn %d ack %d\n", tcp_hdr(skb) -> syn, tcp_hdr(skb) -> ack);
    printk("\tsport %d dport %d\n", ntohs(tcp_hdr(skb) -> source), ntohs(tcp_hdr(skb) -> dest));
    printk("\tsip %u dip %u\n", ntohl(ip_hdr(skb) -> saddr), ntohl(ip_hdr(skb) -> daddr));
    printk("\tid %u %u %u", rkps -> id[0], rkps -> id[1], rkps -> id[2]);
#endif
    bool rtn = rkps -> id[0] == ntohl(ip_hdr(skb) -> saddr)
            && rkps -> id[1] == ntohl(ip_hdr(skb) -> daddr)
            && rkps -> id[2] == (((u_int32_t)ntohs(tcp_hdr(skb) -> source)) << 16) + ntohs(tcp_hdr(skb) -> dest);
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
    if(rkpPacket_seq(p) - rkps -> seq_offset < 0)
    {
#ifdef RKP_DEBUG
        printk("\tsent packet judged.\n");
#endif
        rkpPacket_delete(p);
        return NF_ACCEPT;
    }
    // 已经放到 buff_scan 中的数据包，丢弃
    if(rkpPacket_seq(p) - rkps -> seq_offset < __rkpStream_seq_scanEnd(rkps))
    {
#ifdef RKP_DEBUG
        printk("\tcaptured packet judged.\n");
#endif
        rkpPacket_delete(p);
        return NF_DROP;
    }
    // 恰好是 buff_scan 的后继数据包，这种情况比较麻烦，写到最后
    // 乱序导致还没接收到前继的数据包，放到 buff_disordered
    if(rkpPacket_seq(p) - rkps -> seq_offset > __rkpStream_seq_scanEnd(rkps))
    {
#ifdef RKP_DEBUG
        printk("\tdisordered packet judged.\n");
#endif
        __rkpStream_insert_auto(rkps, &(rkps -> buff_disordered), p);
        return NF_STOLEN;
    }

    // 接下来是恰好是 buff_scan 的后继数据包的情况，先分状态讨论，再一起考虑 buff_disordered 中的包
    if(rkpPacket_seq(p) - rkps -> seq_offset == __rkpStream_seq_scanEnd(rkps))
    {
        // 因为一会儿可能还需要统一考虑 buff_disordered 中的包，因此不直接 return，将需要的返回值写到这里，最后再 return
        // 可以先假定 rtn 是 NF_STOLEN，只有在以下几种情况下才会将返回值改为 NF_ACCEPT
        //      * sniffing 状态下，扫描到了 http 头的结尾，无论是否改 ua，反正都是要 accept
        //      * sniffing 状态下，没有读到 http 头的结尾，但是有设置 psh
        //      * waiting 状态下
        unsigned rtn = NF_STOLEN;
#ifdef RKP_DEBUG
        printk("\tdesired packet judged.\n");
        rkpPacket_makeWriteable(p);
        unsigned char* temp = rkpMalloc((rkpPacket_appLen(p) + 1) * sizeof(unsigned char));
        memcpy(temp, rkpPacket_appBegin(p), rkpPacket_appLen(p));
        temp[rkpPacket_appLen(p)] = 0;
        printk("\tcontent length: %d\n", rkpPacket_appLen(p));
        printk("\tpacket content: %s\n", temp);
        printk("\tpacket content in int:");
        for(rtn = 0; rtn < rkpPacket_appLen(p); rtn++)
            printk("%d\n", rkpPacket_appBegin(p)[rtn]);
        rtn = NF_STOLEN;
        printk("\n");
        rkpFree(temp);
#endif
        // 如果是在 sniffing 的情况下，那一定先丢到 buff_scan 里，然后扫描一下看结果
        if(rkps -> status == __rkpStream_sniffing)
        {
#ifdef RKP_DEBUG
            printk("\t\tsniffing.\n");
#endif
            // 作任何应用层的读取和写入之前，都需要 writeable，而只有这种情况需要做。
            rkpPacket_makeWriteable(p);
            // 丢到 buff_scan 里，记得一会儿如果要 accept，还要拿出来，以及更新序列号
            __rkpStream_insert_end(rkps, &rkps -> buff_scan, p);
            if(__rkpStream_scan(rkps, p))     // 扫描到了 http 头的结尾
            {
#ifdef RKP_DEBUG
                printk("\t\t\thttp head end matched.\n");
#endif
                // 替换 ua
                __rkpStream_modify(rkps);
                // 发出数据包，注意最后一个不发，等会儿 accept 就好
                struct rkpPacket* p2;
                for(p2 = rkps -> buff_scan; p2 != 0 && p2 -> next != 0;)
                {
                    struct rkpPacket* p3 = p2;
                    p2 = p2 -> next;
                    // rkps -> seq_offset = rkpPacket_seq(p2) + rkpPacket_appLen(p2); 不需要更新偏移，因为最后一个包等会儿 accept 的时候会更新
                    rkpPacket_send(p2);
                }
                // 如果没有 psh，设定状态为等待
                if(!rkpPacket_psh(p))
                    rkps -> status = __rkpStream_waiting;
                // 将最后一个包再拿出来，将链表清空，更新偏移，以及把用不到的删掉
                rkps -> buff_scan = 0;
                p -> prev = 0;
                rkps -> seq_offset = rkpPacket_seq(p) + rkpPacket_appLen(p);
                rkpPacket_delete(p);
                // accept
                rtn = NF_ACCEPT;
            }
            // 没有扫描到但是有 psh，同样要全部发出并 accept
            else if(rkpPacket_psh(p))
            {
#ifdef RKP_DEBUG
                printk("rkp-ua: rkpStream_execute: psh found before http head end.\n");
#endif
                // 发出数据包，注意最后一个不发，等会儿 accept 就好
                struct rkpPacket* p2;
                for(p2 = rkps -> buff_scan; p2 != 0 && p2 -> next != 0;)
                {
                    struct rkpPacket* p3 = p2;
                    p2 = p2 -> next;
                    // rkps -> seq_offset = rkpPacket_seq(p2) + rkpPacket_appLen(p2); 不需要更新偏移，因为最后一个包等会儿 accept 的时候会更新
                    rkpPacket_send(p2);
                }
                // 将最后一个包再拿出来，将链表清空，更新偏移，以及把用不到的删掉
                rkps -> buff_scan = 0;
                p -> prev = 0;
                rkps -> seq_offset = rkpPacket_seq(p) + rkpPacket_appLen(p);
                rkpPacket_delete(p);
                // accept
                rtn = NF_ACCEPT;
            }
            // 没有扫描到也没有 psh，偷走就好了，不需要任何操作
            else
            {
#ifdef RKP_DEBUG
                printk("rkp-ua: rkpStream_execute: head end not found.\n");
#endif
            }
        }
        else    // waiting 的状态，检查 psh、设置序列号偏移、然后放行就可以了
        {
#ifdef RKP_DEBUG
            printk("\t\twaiting.\n");
#endif
            rkps -> seq_offset = rkpPacket_seq(p) + rkpPacket_appLen(p);
            if(rkpPacket_psh(p))
                rkps -> status = __rkpStream_sniffing;
            rkpPacket_delete(p);
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
                    rkps -> buff_disordered = p2 -> next;
                    rkps -> buff_disordered -> prev = 0;
                    p2 -> next = 0;
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

int32_t __rkpStream_seq_scanEnd(struct rkpStream* rkps)
{
    struct rkpPacket* rkpp = rkps -> buff_scan;
    if(rkpp == 0)
        return 0;
    else
        for(; ; rkpp = rkpp -> next)
            if(rkpp -> next == 0)
                return rkpPacket_seq(rkpp) - rkps -> seq_offset + rkpPacket_appLen(rkpp);
    
}

void __rkpStream_insert_auto(struct rkpStream* rkps, struct rkpPacket** buff, struct rkpPacket* p)
{
#ifdef RKP_DEBUG
    printk("rkp-ua: __rkpStream_insert_auto start.\n");
#endif
    // 如果链表是空的，那么就直接加进去
    if(*buff == 0)
    {
#ifdef RKP_DEBUG
        printk("rkp-ua: __rkpStream_insert_auto: empty buff.\n");
#endif
        *buff = p;
        p -> prev = p -> next = 0;
    }
    // 又或者，要插入的包需要排到第一个，或者和第一个序列号重复了
    else if(rkpPacket_seq(*buff) - rkps -> seq_offset >= rkpPacket_seq(p) - rkps -> seq_offset)
    {
        if(rkpPacket_seq(*buff) - rkps -> seq_offset == rkpPacket_seq(p) - rkps -> seq_offset)
        {
#ifdef RKP_DEBUG
            printk("rkp-ua: __rkpStream_insert_auto: same seq. Drop it.\n");
#endif
            rkpPacket_drop(p);
        }
        else
        {
            (*buff) -> prev = p;
            p -> next = *buff;
            p -> prev = 0;
            *buff = p;
        }
    }
    // 接下来寻找最后一个序列号不比 p 大的包，插入到它的后面或者丢掉。
    else
    {
        struct rkpPacket* p2 = *buff;
        while(p2 -> next != 0 && rkpPacket_seq(p2 -> next) - rkps -> seq_offset <= rkpPacket_seq(p) - rkps -> seq_offset)
            p2 = p2 -> next;
        if(rkpPacket_seq(p2) - rkps -> seq_offset == rkpPacket_seq(p) - rkps -> seq_offset)
        {
#ifdef RKP_DEBUG
            printk("rkp-ua: __rkpStream_insert_auto: same seq. Drop it.\n");
#endif
            rkpPacket_drop(p);
        }
        else
        {
            p -> next = p2 -> next;
            p -> prev = p2;
            if(p -> next != 0)
                p -> next -> prev = p;
            p2 -> next = p;
        }
    }
#ifdef RKP_DEBUG
    printk("rkp-ua: __rkpStream_insert_auto end.\n");
#endif
}
void __rkpStream_insert_end(struct rkpStream* rkps, struct rkpPacket** buff, struct rkpPacket* p)
{
#ifdef RKP_DEBUG
    printk("rkp-ua: __rkpStream_insert_end start.\n");
#endif
    if(*buff == 0)
    {
        *buff = p;
        p -> next = p -> prev = 0;
    }
    else
    {
        struct rkpPacket* p2 = *buff;
        while(p2 -> next != 0)
            p2 = p2 -> next;
        p2 -> next = p;
        p -> prev = p2;
        p -> next = 0;
    }
#ifdef RKP_DEBUG
    printk("rkp-ua: __rkpStream_insert_end end.\n");
#endif
}
struct rkpPacket* __rkpStream_pop_end(struct rkpStream* rkps, struct rkpPacket** buff)
{
#ifdef RKP_DEBUG
    printk("rkp-ua: __rkpStream_pop_end start.\n");
#endif
    if(*buff == 0)
    {
        printk("__rkpStream_pop_end: pop from an empty list.\n");
        return 0;
    }
    else
    {
        struct rkpPacket* rkpp;
        for(rkpp = *buff; rkpp -> next != 0; rkpp = rkpp -> next);
        if(rkpp -> prev == 0)
            *buff = 0;
        else
            rkpp -> prev = rkpp -> prev -> next = 0;
        return rkpp;
    }
#ifdef RKP_DEBUG
    printk("rkp-ua: __rkpStream_insert_end end.\n");
#endif
}


bool __rkpStream_scan(struct rkpStream* rkps, struct rkpPacket* rkpp)
{
#ifdef RKP_DEBUG
    printk("rkp-ua: __rkpStream_scan start.\n");
#endif
    unsigned char* p;
    for(p = rkpPacket_appBegin(rkpp); p != rkpPacket_appEnd(rkpp); p++)
    {
#ifdef RKP_DEBUG
        printk("rkp-ua: __rkpStream_scan matching %c.\n", *p);
#endif
        if(*p == str_head_end[rkps -> scan_matched])
            rkps -> scan_matched++;
        else
            rkps -> scan_matched = 0;
        if(rkps -> scan_matched == strlen(str_head_end))
        {
            rkps -> scan_matched = 0;
#ifdef RKP_DEBUG
            printk("rkp-ua: __rkpStream_scan: head end found.\n");
            printk("rkp-ua: __rkpStream_scan end.\n");
#endif
            return true;
        }
    }
#ifdef RKP_DEBUG
    printk("rkp-ua: __rkpStream_scan: head end not found.\n");
    printk("rkp-ua: __rkpStream_scan end.\n");
#endif
    return false;
}
void __rkpStream_modify(struct rkpStream* rkps)
{
#ifdef RKP_DEBUG
    printk("rkp-ua: __rkpStream_modify start.\n");
#endif
    unsigned ua_begin_matched = 0, ua_end_matched = 0, head_end_matched = 0, *keyword_matched, ua_relplaced = 0;
    unsigned char *ua_begin_p, *ua_end_p;
    struct rkpPacket *ua_begin_rkpp, *ua_end_rkpp, *rkpp = rkps -> buff_scan;

    // 匹配 "User-Agent: " 的阶段
#ifdef RKP_DEBUG
    printk("matching User-Agent: \n");
#endif
    for(;rkpp != 0 && ua_begin_matched != strlen(str_ua_begin); rkpp = rkpp -> next)
    {
        unsigned char* p;
        for(p = rkpPacket_appBegin(rkpp); p != rkpPacket_appEnd(rkpp); p++)
        {
#ifdef RKP_DEBUG
            printk("rkp-ua: __rkpStream_modify: matching %c.\n", *p);
#endif
            // 检查匹配 http 头结尾的情况
            if(*p == str_head_end[head_end_matched])
            {
                head_end_matched++;
#ifdef RKP_DEBUG
                printk("rkp-ua: __rkpStream_modify: head end matched.\n");
#endif
            }
            else
                head_end_matched = 0;
            if(head_end_matched == strlen(str_head_end))
            {
#ifdef RKP_DEBUG
                printk("rkp-ua: __rkpStream_modify: ua not found.\n");
                printk("rkp-ua: __rkpStream_scan end.\n");
#endif
                return;
            }

            // 检查匹配 "User-Agent: " 的情况
            if(*p == str_ua_begin[ua_begin_matched])
            {
                ua_begin_matched++;
#ifdef RKP_DEBUG
                printk("rkp-ua: __rkpStream_modify: ua begin matched.\n");
#endif
            }
            else
                ua_begin_matched = 0;
            if(ua_begin_matched == strlen(str_ua_begin))
            {
#ifdef RKP_DEBUG
                printk("rkp-ua: __rkpStream_modify: ua found.\n");
#endif
                // 如果是这个包中最后一个字节了，那么跳到下一个包的第一个字节；否则，移动到下一个字节
                if(p == rkpPacket_appEnd(rkpp) - 1)
                {
                    rkpp = rkpp -> next;
                    p = rkpPacket_appBegin(rkpp);
                }
                else
                    p++;
                // 将结果记录进去
                ua_begin_rkpp = rkpp;
                ua_begin_p = p;
                break;
            }
        }
    }
    
    // 匹配 "\r\n" 和需要忽略的关键字的阶段
#ifdef RKP_DEBUG
    printk("matching \\r\\n\n");
#endif
    if(n_str_preserve > 0)
    {
        keyword_matched = rkpMalloc(n_str_preserve * sizeof(unsigned));
        memset(keyword_matched, 0, n_str_preserve * sizeof(unsigned));
    }
    for(rkpp = ua_begin_rkpp; rkpp != 0 && ua_end_matched != strlen(str_ua_end); rkpp = rkpp -> next)
    {
        unsigned char* p;
        if(rkpp == ua_begin_rkpp)
            p = ua_begin_p;
        else
            p = rkpPacket_appBegin(rkpp);
        for(; p != rkpPacket_appEnd(rkpp); p++)
        {
            // 检查匹配 "\r\n" 的情况
#ifdef RKP_DEBUG
            printk("rkp-ua: __rkpStream_modify: matching %c.\n", *p);
#endif
            if(*p == str_ua_end[ua_end_matched])
            {
                ua_end_matched++;
#ifdef RKP_DEBUG
                printk("rkp-ua: __rkpStream_modify: ua end matched.\n");
#endif
            }
            else
                ua_end_matched = 0;
            if(ua_end_matched == strlen(str_ua_end))
            {
#ifdef RKP_DEBUG
                printk("rkp-ua: __rkpStream_modify: ua end found.\n");
#endif
                // 如果在某个包的开头几个字节匹配结束（即 ua 实际上全部位于上一个包），就返回去
                if(p + 1 - rkpPacket_appBegin(rkpp) <= strlen(str_ua_end))
                {
#ifdef RKP_DEBUG
                    printk("rkp-ua: __rkpStream_modify: move to last packet.\n");
#endif
                    unsigned temp = strlen(str_ua_end) - (p + 1 - rkpPacket_appBegin(rkpp));    // str_ua_end 位于上一个包中的长度
                    rkpp = rkpp -> prev;
                    p = rkpPacket_appEnd(rkpp) - temp;
                }
                // 否则，回退到 ua 结束的位置
                else
                    p += 1 - strlen(str_ua_end);
                // 记录结果
                ua_end_rkpp = rkpp;
                ua_end_p = p;
                // 记得删掉不用的内存
                if(n_str_preserve > 0)
                    rkpFree(keyword_matched);
                break;
            }

            // 检查匹配需要忽略的关键字的情况
            unsigned i;
            for(i = 0; i < n_str_preserve; i++)
            {
                if(*p == str_preserve[i][keyword_matched[i]])
                    keyword_matched[i]++;
                else
                    keyword_matched[i] = 0;
                if(keyword_matched[i] == strlen(str_preserve[i]))
                {
#ifdef RKP_DEBUG
                    printk("rkp-ua: __rkpStream_modify: keyword %s matched.\n", str_preserve[i]);
                    printk("rkp-ua: __rkpStream_scan end.\n");
#endif
                    rkpFree(keyword_matched);
                    return;
                }
            }
        }
    }

    // 已经获得了所需要的信息并且确认 ua 需要替换，然后替换 ua 的阶段
    // 已经全部 writeable，可以放心大胆地替换字符串
#ifdef RKP_DEBUG
    printk("rkp-ua: __rkpStream_modify: ua modify start.\n");
#endif
    for(rkpp = ua_begin_rkpp; ; rkpp = rkpp -> next)
    {
        unsigned char* p;
        if(rkpp == ua_begin_rkpp)
            p = ua_begin_p;
        else
            p = rkpPacket_appBegin(rkpp);
        for(; p != rkpPacket_appEnd(rkpp) && p != ua_end_p; p++)
        {
            if(ua_relplaced < strlen(str_ua_rkp))
                *p = str_ua_rkp[ua_relplaced];
            else
                *p = ' ';
            ua_relplaced++;
        }
        if(rkpp == ua_end_rkpp)
            break;
    }
    // 重新计算校验和
#ifdef RKP_DEBUG
    printk("rkp-ua: __rkpStream_modify: skb checksum start.\n");
#endif
    for(rkpp = ua_begin_rkpp; rkpp != 0 && rkpp -> prev != ua_end_rkpp; rkpp = rkpp -> next)
        rkpPacket_csum(rkpp);
}
