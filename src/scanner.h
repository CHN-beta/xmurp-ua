#include <linux/module.h>
#include <linux/version.h>
#include <linux/kmod.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/types.h>

const char str_ua[] const = "User-Agent: ";
const char str_headtail[] const = "\r\n\r\n";
const char str_uaend[] const = "\r\n";
const char str_windows[] const = "Windows NT";

struct scanner
// 字符串扫描（跨 skb）需要的一些状态变量以及函数
{
    struct sk_buff* skb;        // 当前正在扫描的字符所在的 skb
    char* data_start;
    char* data_end;             // skb 的应用层起始位置和终止位置，记下来避免每次计算
    char* pos;                  // 现在扫描到的位置

    const char* target;         // 要匹配的字符串
    u_int8_t target_legth;      // 要匹配的字符串的长度

    u_int8_t enum
    {
        matching_none,
        matching_content,
        matching_headtail
    } matching_status;          // 当前匹配的状态：没有正在匹配的，正在匹配所给的内容，正在匹配 http 头结尾
    u_int16_t matched_length;   // 如果正在匹配给定的内容或者头结尾，这里指示已经匹配的长度（包含当前的字符）
};
void scanner_init(struct scanner* scn, struct sk_buff* skb, u_int16_t pos, const char* target)
// 初始化扫描器
// pos 指指针相对于给定的 skb 的应用层第一个字节的位置。skb 的第一个应用层字节的位置为 0。
{
    // 找到目标字节真正所的 skb
    while(true)
    {
        register struct tcphdr *tcph = tcp_hdr(skb);
	    register struct iphdr *iph = ip_hdr(skb);
        u_int16_t data_length = ntohs(iph -> tot_len) - iph -> ihl * 4 - tcph -> doff * 4;
        if(pos >= data_length)
            pos -= data_length;
    }
    scn -> skb = skb;
    scn -> data_start = (char*)tcph + tcph -> doff * 4;
    scn -> data_end = (char*)tcph + ntohs(iph -> tot_len) - iph -> ihl * 4;
    scn -> pos = scn -> data_start + pos;
    scn -> target = target;
    scn -> target_length = strlen(target);
    scn -> matching_status = scn -> matching_none;
    scn -> matched_length = 0;
}
u_int8_t scanner_next(struct scanner* scn)
// 尝试将指针移动到下一个字节。会自动跨 skb。
// 返回值：0 没有匹配完毕什么；1 目标字符串匹配完毕；2 http 头匹配完毕；-1 需要下一个 skb（下一个 skb 的指针是 0，或者根据序列判断并不是紧邻的下一个 skb
// 注意到，如果要匹配 "\r\n" 之类以 '\r' 开头的字符串时，不能正确地识别 http 头结尾；以及，匹配长度为 1 的字符串时也会出错。但这并不影响最终结果。
{
    // 尝试将指针移动到下一个位置
    if(scn -> pos + 1 == scn -> data_end)
    {
        if(scn -> skb -> next == 0)
            return -1;
        else
        {
            register u_int32_t target_seq = ntohl(tcp_hdr(scn -> skb) -> seq) + (scn -> data_end - scn -> data_start);
            if(target_seq != ntolh(scn -> skb -> next -> seq))
                return -1
            else
            {
                scn -> skb = scn -> skb -> next;
                register struct tcphdr *tcph = tcp_hdr(scn -> skb);
	            register struct iphdr *iph = ip_hdr(scn -> skb);
                scn -> data_start = (char*)tcph + tcph -> doff * 4;
                scn -> data_end = (char*)tcph + ntohs(iph -> tot_len) - iph -> ihl * 4;
                scn -> pos = scn -> data_start;
            }
        }
    }
    else
        scn -> pos++;

    // 检查匹配情况
    if(scn -> matching_status == scn -> matching_none)
    {
        if(scn -> pos[0] == scn -> target[0])
        {
            scn -> matching_status == scn -> matching_target;
            scn -> matched_length = 1;
            return 0;
        }
        else if(scn -> pos[0] == str_headtail[0])
        {
            scn -> matching_status == scn -> matching_headtail;
            scn -> matched_length = 1;
            return 0;
        }
        else
            return 0;
    }
    else if(scn -> matching_status == scn -> matching_target)
    {
        if(scn -> pos[0] == scn -> target[scn -> matched_length])
        {
            scn -> matched_length++;
            if(scn -> matched_length == scn -> matched_length)
                return 1;
            else
                return 0;
        }
        else if(scn -> pos[0] == str_headtail[0])
        {
            scn -> matching_status == scn -> matching_headtail;
            scn -> matched_length = 1;
            return 0;
        }
        else
        {
            scn -> matching_status == scn -> matching_none;
            scn -> matched_length = 0;
            return 0;
        }
    }
    else if(scn -> matching_status == scn -> matching_target)
    {
        if(scn -> pos[0] == str_headtail[scn -> matched_length])
        {
            scn -> matched_length++;
            if(scn -> matched_length == 4)
                return 2;
            else
                return 0;
        }
        else if(scn -> pos[0] == scn -> target[0])
        {
            scn -> matching_status == scn -> matching_target;
            scn -> matched_length = 1;
            return 0;
        }
        else
        {
            scn -> matching_status == scn -> matching_none;
            scn -> matched_length = 0;
            return 0;
        }
    }
}
void scanner_prev(struct scanner* scn)
// 将指针移动到上一个字节。会自动跨 skb。
// 不需要考虑匹配的状态。保证上一个 skb 一定存在。
{
    if(scn -> pos == scn -> data_start)
    {
        scn -> skb = scn -> skb -> prev;
        register struct tcphdr *tcph = tcp_hdr(scn -> skb);
        register struct iphdr *iph = ip_hdr(scn -> skb);
        scn -> data_start = (char*)tcph + tcph -> doff * 4;
        scn -> data_end = (char*)tcph + ntohs(iph -> tot_len) - iph -> ihl * 4;
        scn -> pos = scn -> data_end - 1;
    }
    else
        scn -> pos--;
}
void scanner_next_noscan(struct scanner* scn)
{
    if(scn -> pos + 1 == scn -> data_end)
    {
        scn -> skb = scn -> skb -> next;
        register struct tcphdr *tcph = tcp_hdr(scn -> skb);
        register struct iphdr *iph = ip_hdr(scn -> skb);
        scn -> data_start = (char*)tcph + tcph -> doff * 4;
        scn -> data_end = (char*)tcph + ntohs(iph -> tot_len) - iph -> ihl * 4;
        scn -> pos = scn -> data_start;
    }
    else
        scn -> pos++;
}