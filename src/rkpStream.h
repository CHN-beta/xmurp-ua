#include "rkpSettings.h"

struct rkpStream
{
    enum
    {
        rkpStream_sniffing,
        rkpStream_waiting
    } status;
    u_int32_t id[3];        // 按顺序存储客户地址、服务地址、客户端口、服务端口，已经转换字节序
    struct sk_buff *buff, *buff_prev, *buff_next;   // 都按照字节序排好了
    u_int32_t ack;     // 服务端已经确认收到的最后一个字节的序列号。以后所有的相对序列号都是将这个序号视为零的相对序列号。
    u_int32_t seq;     // 已经收到的最后一个字节的序列号。期待的序列号应该比它加1。
    time_t last_active;
    bool scan_matched;
    bool preserve;
    struct rkpStream *prev, *next;
};

struct rkpStream* rkpStream_new(const struct sk_buff*);                   // 构造函数，得到的流的状态是捕获这个数据包之后的状态。内存不够时返回 0。
void rkpStream_del(struct rkpStream*);                              // 析构函数
bool rkpStream_belong(const struct rkpStream*, const struct sk_buff*);      // 判断一个数据包是否属于一个流
unsigned rkpStream_execute(struct rkpStream*, struct sk_buff*);     // 处理一个数据包（假定包属于这个流）

void __rkpStream_refresh_ack(struct rkpStream*, u_int32_t);         // 刷新确认序列号。第二个参数就是ack包中的确认号（绝对值）减一，表明已经确认到了哪个位置。会自动重新计算序列号的偏移，以及释放 buff_prev 中的多余数据包

unsigned char* __rkpStream_skb_appBegin(const struct sk_buff*);           // 返回一个包的应用层数据起始位置
u_int16_t __rkpStream_skb_appLen(const struct sk_buff*);                  // 返回一个包的应用层数据长度
int32_t __rkpStream_skb_seq(u_int32_t, u_int32_t);                  // 返回一个序列号的相对序列号。两个参数分别为流的确认号、包的序列号（已经转换字节序）。可以为负。

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
    struct rkpStream* rkps = kmalloc(sizeof(struct rkpStream), GFP_KERNEL);
    const struct iphdr* iph = ip_hdr(skb);
    const struct tcphdr* tcph = tcp_hdr(skb);

    if(rkps == 0)
    {
        printk("rkp-ua::rkpStream::rkpStream_new: `kmalloc` failed, may caused by shortage of memory.\n");
        return 0;
    }
    rkps -> status = rkpStream_sniffing;
    rkps -> id[0] = ntohl(iph -> saddr);
    rkps -> id[1] = ntohl(iph -> daddr);
    rkps -> id[2] = (((u_int32_t)ntohs(tcph -> source)) << 16) + ntohs(tcph -> dest);
    rkps -> buff = rkps -> buff_prev = rkps -> buff_next = 0;
    rkps -> ack = ntohl(tcph -> seq) - 1;
    rkps -> seq = 1;
    rkps -> last_active = now();
    rkps -> scan_matched = 0;
    rkps -> preserve = rkpSettings_preserve(skb);
    rkps -> prev = rkps -> next = 0;
    return rkps;
}
void rkpStream_del(struct rkpStream* rkps)
{
    kfree_skb_list(rkps -> buff);
    kfree_skb_list(rkps -> buff_prev);
    kfree_skb_list(rkps -> buff_next);
    kfree(rkps);
}
bool rkpStream_belong(const struct rkpStream* rkps, const struct sk_buff* skb)
{
#ifdef RKP_DEBUG
    printk("rkpStream_belong:\n");
    printk("\tsyn %d ack %d\n", tcp_hdr(skb) -> syn, tcp_hdr(skb) -> ack);
    printk("\tsport %d dport %d\n", ntohs(tcp_hdr(skb) -> source), ntohs(tcp_hdr(skb) -> dest));
    printk("\tsip %u dip %u\n", ntohl(ip_hdr(skb) -> saddr), ntohl(ip_hdr(skb) -> daddr));
    printk("\trkpSettings_request %d\n", rkpSettings_request(skb));
    printk("\tid %u %u %u", rkps -> id[0], rkps -> id[1], rkps -> id[2]);
#endif
    if(rkpSettings_request(skb))
    {
        if(rkps -> id[0] != ntohl(ip_hdr(skb) -> saddr))
            return false;
        if(rkps -> id[1] != ntohl(ip_hdr(skb) -> daddr))
            return false;
        if(rkps -> id[2] != (((u_int32_t)ntohs(tcp_hdr(skb) -> source)) << 16) + ntohs(tcp_hdr(skb) -> dest))
            return false;
        return true;
    }
    else
    {
        if(rkps -> id[0] != ntohl(ip_hdr(skb) -> daddr))
        {
#ifdef RKP_DEBUG
            printk("\t 0 not match.\n");
#endif
            return false;
        }
        if(rkps -> id[1] != ntohl(ip_hdr(skb) -> saddr))
        {
#ifdef RKP_DEBUG
            printk("\t 1 not match.\n");
#endif
            return false;
        }
        if(rkps -> id[2] != (((u_int32_t)ntohs(tcp_hdr(skb) -> dest)) << 16) + ntohs(tcp_hdr(skb) -> source))
        {
#ifdef RKP_DEBUG
            printk("\t 2 not match.\n");
#endif
            return false;
        }
        return true;
    }
}
unsigned rkpStream_execute(struct rkpStream* rkps, struct sk_buff* skb)
// 不要害怕麻烦，咱们把每一种情况都慢慢写一遍。
{
    int32_t seq;
#ifdef RKP_DEBUG
    printk("rkpStream_execute\n");
#endif

    // 肯定需要更新时间
    rkps -> last_active = now();

    // 服务端返回确认包的情况，更新一下确认号，返回 sccept。以后的情况，都是客户端发往服务端的了。
    if(!rkpSettings_request(skb))
    {
#ifdef RKP_DEBUG
        printk("DEBUG0\n");
#endif
        int32_t seq = __rkpStream_skb_seq(rkps -> ack, ((unsigned)(ntohl(tcp_hdr(skb) -> ack_seq))) - 1);
        if(seq > 0)
            __rkpStream_refresh_ack(rkps, ((unsigned)(ntohl(tcp_hdr(skb) -> ack_seq))) - 1);
        return NF_ACCEPT;
    }

    // 不携带应用层数据的情况。除了首包，直接接受即可。以后的情况，都是含有应用层数据的包了。
    if(__rkpStream_skb_appLen(skb) == 0)
    {
#ifdef RKP_DEBUG
        printk("DEBUG1\n");
#endif
        return NF_ACCEPT;
    }
    
    // 检查数据包是否是将来的数据包。如果是的话，需要放到 buff_next 等待处理。
    seq = __rkpStream_skb_seq(rkps -> ack, ntohl(tcp_hdr(skb) -> seq));
#ifdef RKP_DEBUG
    printk("seq %d\n", seq);
#endif
    if(seq > rkps -> seq + 1)
    {
#ifdef RKP_DEBUG
        printk("DEBUG2\n");
#endif
        skb = __rkpStream_skb_copy(skb);
        if(skb == 0)
            return NF_ACCEPT;
        __rkpStream_buff_retain_auto(&(rkps -> buff_next), __rkpStream_skb_copy(skb));
        return NF_DROP;
    }

    // 检查数据包是否是已经被确认的数据包。应该不会出现这种情况（除了不带数据的 keep alive，但这已经考虑过了）。出现的话就把它丢掉吧。
    if(seq < 0)
    {
        printk("rkp-ua::rkpStream: Re-transmission of asked package. Drop it.\n");
        return NF_DROP;
    }

    // 检查数据包是否是重传数据包。如果是的话，可能需要修改数据。然后，将它发出。接下来的情况，就一定是刚好是需要的序列号的情况了
    if(seq < rkps -> seq + 1)
    {
#ifdef RKP_DEBUG
        printk("DEBUG3\n");
#endif
        const struct sk_buff* skb_prev = __rkpStream_buff_find(rkps -> buff_prev, ntohl(tcp_hdr(skb) -> seq));
        if(skb_prev != 0 && tcp_hdr(skb_prev) -> seq == tcp_hdr(skb) -> seq)
        // 存在相符的数据包。将数据拷贝过去。
        {
            if(skb_ensure_writable(skb, __rkpStream_skb_appBegin(skb) + __rkpStream_skb_appLen(skb) - skb -> data))
            {
                printk("rkp-ua::rkpStream::rkpStream_execute: Can not make skb writable, may caused by shortage of memory. Drop it.\n");
                return NF_DROP;
            }
            if(__rkpStream_skb_appLen(skb_prev) != __rkpStream_skb_appLen(skb))
            {
                printk("rkp-ua::rkpStream::rkpStream_execute: Size of app data in re-transmission package and previous one not match. Drop it.\n");
                return NF_DROP;
            }
            memcpy(__rkpStream_skb_appBegin(skb), __rkpStream_skb_appBegin(skb_prev), __rkpStream_skb_appLen(skb_prev));
        }
        return NF_ACCEPT;
    }

    // 如果是在 sniffing 的情况下，那一定先扫描一下再说
    if(rkps -> status == rkpStream_sniffing)
    {
#ifdef RKP_DEBUG
        printk("DEBUG4\n");
#endif
        u_int16_t scan = __rkpStream_data_scan(__rkpStream_skb_appBegin(skb), __rkpStream_skb_appLen(skb),
                str_head_end, rkps -> scan_matched);
        
        if(scan & 0x1)
        // 扫描找到了 HTTP 头的结尾，那么将这个数据包补到 buff 中，更新 seq，开始查找、替换、发出，然后根据情况设置状态，再考虑 buff_next 中的包，最后返回 STOLEN
        {
#ifdef RKP_DEBUG
            printk("DEBUG5\n");
#endif
            struct sk_buff* skbp;

            skb = __rkpStream_skb_copy(skb);
            if(skb == 0)
                return NF_ACCEPT;

            // 追加到 buff 后面，更新 seq
            __rkpStream_buff_retain_end(&(rkps -> buff), skb);
            rkps -> seq = __rkpStream_skb_seq(rkps -> ack, ntohl(tcp_hdr(skb) -> seq)) + __rkpStream_skb_appLen(skb) - 1;

            // 查找、替换
            __rkpStream_buff_execute_core(&(rkps -> buff), scan >> 1, rkps -> preserve);

#ifdef RKP_DEBUG
            // return NF_ACCEPT;
#endif

            // 循环复制一份到 buff_prev 下面，同时发出
            skbp = rkps -> buff;
            while(skbp != 0)
            {
                struct sk_buff* skbp2 = skbp -> next;
                __rkpStream_buff_retain_end(&(rkps -> buff_prev), __rkpStream_skb_copy(skbp));
                __rkpStream_skb_send(skbp);
                skbp = skbp2;
            }
            rkps -> buff = 0;

            // 清空查找情况，重新设置状态
            rkps -> scan_matched = 0;
            if(!(tcp_hdr(skb) -> psh))
                rkps -> status = rkpStream_waiting;

            // 考虑之前截留的数据包
            __rkpStream_buff_rejudge(rkps, &(rkps -> buff_next));

            return NF_DROP;
        }
        else if(tcp_hdr(skb) -> psh)
        // 如果没有找到却读到了 PUSH，这就比较迷了。打印一句警告，更新 seq，然后把截留的包都放行，然后考虑 buff_next 里的数据。
        {
            struct sk_buff* skbp = rkps -> buff;

            // 打印警告
            printk("rkp-ua::rkpStream::rkpStream_execute: Find PSH before header ending found. Send without modification.\n");

            // 更新 seq
            rkps -> seq = __rkpStream_skb_seq(rkps -> ack, ntohl(tcp_hdr(skb) -> seq)) + __rkpStream_skb_appLen(skb) - 1;

            // 放行截留的包
            while(skbp != 0)
            {
                struct sk_buff* skbp2 = skbp -> next;
                __rkpStream_skb_send(skbp);
                skbp = skbp2;
            }
            rkps -> buff = 0;

            // 清空查找情况
            rkps -> scan_matched = 0;

            // 考虑之前截留的数据包
            __rkpStream_buff_rejudge(rkps, &(rkps -> buff_next));

            return NF_ACCEPT;
        }
        else
        // 没有找到结尾，也没有push。那么，将这个数据包补到 buff 中，更新 seq 和 查找状态，再考虑 buff_next 中的包，最后返回 STOLEN
        {
#ifdef RKP_DEBUG
            printk("DEBUG6\n");
#endif

            skb = __rkpStream_skb_copy(skb);
            if(skb == 0)
                return NF_ACCEPT;

            // 追加到 buff
            __rkpStream_buff_retain_end(&(rkps -> buff), skb);

            // 更新 seq 和查找状态
            rkps -> seq = __rkpStream_skb_seq(rkps -> ack, ntohl(tcp_hdr(skb) -> seq)) + __rkpStream_skb_appLen(skb) - 1;
            rkps -> scan_matched = scan >> 1;

            // 考虑 buff_next 中的包
            __rkpStream_buff_rejudge(rkps, &(rkps -> buff_next));

            return NF_DROP;
        }
    }
    else
    // 如果是在 waiting 的状态下，那么设置 seq 和状态，然后考虑 buff_next 中的包，然后返回 ACCEPT 就可以了
    {
        printk("DEBUG7\n");
        // 设置 seq 和状态
        rkps -> seq = __rkpStream_skb_seq(rkps -> ack, ntohl(tcp_hdr(skb) -> seq)) + __rkpStream_skb_appLen(skb) - 1;
        if(tcp_hdr(skb) -> psh)
            rkps -> status = rkpStream_sniffing;
        
        // 考虑 buff_next
        __rkpStream_buff_rejudge(rkps, &(rkps -> buff_next));

        return NF_ACCEPT;
    }
}

void __rkpStream_refresh_ack(struct rkpStream* rkps, u_int32_t ack)
{
    struct sk_buff* skbp;

    // 重新计算 ack 和 seq
    rkps -> seq -= ack - rkps -> ack;
    rkps -> ack = ack;

    // 丢弃 buff_prev 中已经确认收到的数据包
    skbp = rkps -> buff_prev;
    while(skbp != 0 && __rkpStream_skb_seq(ack, ntohl(tcp_hdr(skbp) -> ack)) <= 0)
    {
        struct sk_buff* skbp2 = skbp -> next;
        __rkpStream_skb_del(skbp);
        skbp = skbp2;
    }
    rkps -> buff_prev = skbp;
}

unsigned char* __rkpStream_skb_appBegin(const struct sk_buff* skb)
{
    return ((unsigned char*)tcp_hdr(skb)) + tcp_hdr(skb) -> doff * 4;
}

u_int16_t __rkpStream_skb_appLen(const struct sk_buff* skb)
{
    return ntohs(ip_hdr(skb) -> tot_len) - ip_hdr(skb) -> ihl * 4 - tcp_hdr(skb) -> doff * 4;
}

int32_t __rkpStream_skb_seq(u_int32_t ack, u_int32_t seq)
{
    return (int32_t)(seq - ack);
}

void __rkpStream_skb_send(struct sk_buff* skb)
{
    dev_queue_xmit(skb);
}

struct sk_buff* __rkpStream_skb_copy(const struct sk_buff* skb)
{
    struct sk_buff* rtn = skb_copy(skb, GFP_KERNEL);
    if(rtn == 0)
        printk("rkp-ua::rkpStream::__rkpStream_skb_copy: `skb_copy` failed, may caused by shortage of memory.");

#ifdef RKP_DEBUG
    printk("__rkpStream_skb_copy:\n");
    printk("\tcheck if parameter equals.\n");
    printk("\tskb -> dev %d\n", skb -> dev == rtn -> dev);
    printk("\tskb -> pkt_type %d\n", skb -> pkt_type == rtn -> pkt_type);
    printk("\tskb -> protocol %d\n", skb -> protocol == rtn -> protocol);
    printk("\tskb -> ip_summed %d\n", skb -> ip_summed == rtn -> ip_summed);
    printk("\tskb -> priority %d\n", skb -> priority == rtn -> priority);
    printk("\tskb -> csum %d\n", skb -> csum == rtn -> csum);
    printk("\tethh -> h_dest %d\n", eth_hdr(skb) -> h_dest == eth_hdr(rtn) -> h_dest);
    printk("\tethh -> h_source %d\n", eth_hdr(skb) -> h_source == eth_hdr(rtn) -> h_source);
    printk("\tethh -> h_proto %d\n", eth_hdr(skb) -> h_proto == eth_hdr(rtn) -> h_proto);
#endif

    // 链路层数据还需要手动复制一下，我也不知道这是怎么个设计
    memcpy(eth_hdr(rtn), eth_hdr(skb), sizeof(unsigned char) * 2 * ETH_ALEN + sizeof(__be16));

    return skb_copy(skb, GFP_KERNEL);
}
void __rkpStream_skb_del(struct sk_buff* skb)
{
    kfree_skb(skb);
}
void __rkpStream_skb_csum(struct sk_buff* skb)
{
    struct iphdr* iph = ip_hdr(skb);
    struct tcphdr* tcph = tcp_hdr(skb);
    tcph -> check = 0;
    iph -> check = 0;
    skb -> csum = skb_checksum(skb, iph -> ihl * 4, ntohs(iph -> tot_len) - iph -> ihl * 4, 0);
    iph -> check = ip_fast_csum(iph, iph -> ihl);
    tcph -> check = csum_tcpudp_magic(iph -> saddr, iph -> daddr, ntohs(iph -> tot_len) - iph -> ihl * 4, IPPROTO_TCP, skb -> csum);
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
void __rkpStream_buff_rejudge(struct rkpStream* rkps, struct sk_buff** buff)
{
    while(*buff != 0)
    {
        int32_t seq = __rkpStream_skb_seq(rkps -> ack, ntohl(tcp_hdr(*buff) -> seq));
        if(seq <= rkps -> seq)
        // 过期的skb，虽然应该不会出现这样的情况
        {
            struct sk_buff* skb2 = (*buff) -> next;
            __rkpStream_skb_del(*buff);
            *buff = skb2;
        }
        else if(seq == rkps -> seq + 1)
        {
                unsigned rtn;
                struct sk_buff* skb2;

                // 将它从链表中取出
                if((*buff) -> next != 0)
                    (*buff) -> next -> prev = 0;
                skb2 = *buff;
                *buff = (*buff) -> next;                    
                
                // 执行之
                rtn = rkpStream_execute(rkps, skb2);
                if(rtn == NF_ACCEPT)
                    __rkpStream_skb_send(skb2);
                else if(rtn == NF_DROP)
                    __rkpStream_skb_del(skb2);
        }
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