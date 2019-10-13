#include "scanner.h"

struct stm_info
// 用于存储每一条流的信息。
{
    u_int8_t    modify_finished:1,      // 标识是否已经被修改完成。对于修改完成的流，肯定没有存储任何 skb，之后都不会再捕获。对于不需要修改的流，最初的时候就会被置为“已经修改完成”而直接放行。
                modify_force:1,         // 是否强制修改这个流（而不论目标地址，也不论是否是 windows 主机）,与 mark 中的内容对应。
                scan_finished:1,        // 是否已经扫描完成；也就是说，已经完整地找到了 ua，或者完整地拿到了 http 头。之后不再会捕获这个流，但流中可能还有缓存的 skb 没有发出。windows 也已经被扫描（除非没有必要）。
                scan_ua_found:1,        // 是否找到了 ua。只要找到了 "User-Agent: " 这一项就被置为 1，ua_start 同时被设置；ua_end 则会等到 scan_finished 才被设置。
                scan_windows:1,         // ua 是否是 windows 的 ua。在完整地找到 ua 后，除非 modify_force 被设置，否则会再扫描一遍 ua 来确定这个值。
                preserved:3;
    u_int32_t saddr;                    // 源地址
    u_int16_t sport;                    // 源端口。通过这两项应该足够区分不同的流。
    u_int32_t seq_offset;               // 应用层字节的编号的偏移，减去偏移后，第一个应用层字节的编号为 0
    u_int32_t ua_start;                 // "User-Agent: xxxxx\r\n" 中，第一个 'x' 的位置（已经减去偏移）
    u_int32_t ua_end;                   // "User-Agent: xxxxx\r\n?" 中，‘\r’ 的位置（已经减去偏移）
    struct sk_buff* skb;
    struct scanner* scn;
};
void stm_init(struct stm_info* stm, struct sk_buff* skb)
// 初始化 stm_info
{
    stm -> modify_finished = 0;
    if(skb -> mark & 0x20)
        stm -> modify_force = 1;
    else
        stm -> modify_force = 0;
    stm -> scan_finished = 0;
    stm -> saddr = ntohl(ip_hdr(skb) -> daddr);
    stm -> sport = ntohs(tcp_hdr(skb) -> dest);
    stm -> seq_offset = ntohl(tcp_hdr(skb) -> ack_seq);
    stm -> skb = 0;
    stm -> scn = 0;
}
u_int32_t stm_realseq(struct stm_info* stm, struct sk_buff* skb)
// 计算 skb 的真实偏移
{
    register u_int32_t real_seq = ntohl(tcp_hdr(skb) -> ack_seq);
    if(real_seq >= stm -> seq_offset)
        real_seq -= stm -> seq_offset;
    else
        real_seq += 0xffffffff - stm -> seq_offset + 1;
    return real_seq;
}
void stm_append(struct stm_info* stm, struct sk_buff* skb)
// 追加一个 skb 到合适的位置。
{
    register u_int32_t real_seq;
    register struct sk_buff* i;
    if(stm -> skb == 0)
    {
        stm -> skb = skb;
        skb -> next = skb -> prev = 0;
    }

    real_seq = stm_realseq(stm, skb);
    if(stm_realseq(stm, stm -> skb) > real_seq)
    {
        stm -> skb -> prev = skb;
        skb -> next = stm -> skb;
        stm -> skb = skb;
    }

    //尝试寻找最后一个序号比待插入 skb 小的 skb
    for(i = stm -> skb;;i = i -> next)
    {
        if(i -> next == 0)
        {
            i -> next = skb;
            skb -> prev = i;
            skb -> next = 0;
        }
        else if(stm_realseq(stm, i -> next) > real_seq)
        {
            i -> next -> prev = skb;
            skb -> next = i -> next;
            i -> next = skb;
            skb -> prev = i;
        }
    }
}
void stm_scan(struct stm_info* stm)
// 扫描直到头部末尾或者 ua 结束（总之是使得 scan_finished）或者不能再继续扫描了（需要下一个包）。也会扫描 windows，如果有必要。
{
    // 如果没有初始化扫描器，就尝试初始化
    if(stm -> scn == 0)
    {
        if(stm -> skb == 0 || stm_realseq(stm, stm -> skb) != 0)
            return;
        else
        {
            stm -> scn = kmalloc(sizeof(scanner), GFP_KERNEL);
            scanner_init(stm -> scn, stm -> skb, 0, str_ua);
        }
    }

    static char* ua_end = 0;    // 仅仅用来扫描 windows 时使用一下。记录 ua 的结束位置，当扫描到这里时还没有 windows，那就是没有了。
    while(true)
    {
        u_int8_t rtn = scanner_next(stm -> scn);
        if(rtn == 0 && stm -> scn -> pos == ua_end)
        // 没有找到 windows
        {
            stm -> scan_finished = 1;
            ua_end = 0;
        }
        else if(rtn == 0)
            continue;
        else if(rtn == 1 && stm -> scn -> target == str_ua)
        {
            // 将结果记录，然后去扫描 ua 尾。
            stm -> scan_ua_found;
            stm -> ua_start = stm_realseq(stm, stm -> scn -> skb) + (stm -> scn -> pos - stm -> scn -> data_start);
            scanner_init(stm -> scn, stm -> scn -> skb, stm -> scn -> pos - stm -> scn -> data_start, str_uaend);
        }
        else if(rtn == 1 && stm -> scn -> target == str_uaend)
        {
            // 将结果记录，然后去扫描 windows 或者结束。
            stm -> ua_end = stm_realseq(stm, stm -> scn -> skb) + (stm -> scn -> pos - stm -> scn -> data_start) + 1;
            if(!stm -> modify_force)
                scanner_init(stm -> scn, stm -> skb, stm -> ua_start, str_windows);
            else
            {
                stm -> scan_finished = 1;
                return;
            }
        }
        else if(rtn == 1 && stm -> scn -> target == str_windows)
        // 将结果记录，结束
        {
            stm -> scan_windows = 1;
            stm -> scan_finished = 1;
            ua_end = 0;
            return;
        }
        else if(rtn == 2)
        {
            stm -> scan_finished;
            return;
        }
    }
}
void stm_modify_send(struct stm_info* stm)
// 将 ua 替换为 "XMURP/1.0" 加许多的空格
{
    struct sk_buff* skb_start;
    struct sk_buff* skb_end;        // 两个 skb 之间的（包含这两个 skb）都需要重新计算校验和
    sturct sk_buff* skb;
    u_int16_t i;
    scanner_init(stm -> scn, stm -> skb, stm -> ua_start, str_ua);
    skb_start = stm -> scn -> skb;
    scanner_prev(stm -> scn);
    for(int i = 0; i < stm -> ua_end - stm -> ua_start; i++)
    {
        scanner_next_noscan(stm -> scn);
        if(i < strlen("XMURP/1.0"))
            *(stm -> scn -> pos) = "XMURP/1.0"[i];
        else
            *(stm -> scn -> pos) = ' ';
    }
    skb_end = stm -> scn -> skb -> next;

    skb = skb_start;
    do
    {
        register struct tcp_hdr* tcph = tcp_hdr(skb);
        register struct ip_hdr* iph = ip_hdr(skb);
        tcph->check = 0;
		iph->check = 0;
		skb->csum = skb_checksum(skb, iph->ihl * 4, ntohs(iph->tot_len) - iph->ihl * 4, 0);
		iph->check = ip_fast_csum(iph, iph->ihl);
		tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, ntohs(iph->tot_len) - iph->ihl * 4, IPPROTO_TCP, skb->csum);
    }
    while((skb = skb -> next) != skb_end);

    skb = stm -> skb;
    while(skb != 0)
    {
        dev_queue_xmit(skb);
        skb = skb -> next;
    }

    stm -> modify_finished = 1;
}



