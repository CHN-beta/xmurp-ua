#pragma once
#include "rkpSettings.h"
#include "rkpPacket.h"

struct rkpStream
// 接管一个 TCP 流。忽略重传（一律放行）。因此，也不需要捕获来自服务端的包。
{
    enum
    {
        __rkpStream_sniffing_uaBegin,           // 正在寻找 http 头的结尾或者 ua 的开始，这时 buff_scan 中不应该有包
        __rkpStream_sniffing_uaEnd,             // 已经找到 ua，正在寻找它的结尾，buff_scan 中可能有包
        __rkpStream_waiting                     // 已经找到 ua 的结尾或者 http 头的结尾并且还没有 psh，接下来的包都直接放行
    } status;
    u_int32_t id[3];                            // 按顺序存储客户地址、服务地址、客户端口、服务端口，已经转换字节序
    struct rkpPacket *buff_scan, *buff_disordered;      // 分别存储准备扫描的、因乱序而提前收到的数据包，都按照序号排好了
    int32_t seq_offset;                         // 序列号的偏移。使得 buff_scan 中第一个字节的编号为零。
    bool active;                                // 是否仍然活动，流每次处理的时候会置为 true，每隔一段时间会删除标志为 false（说明它在这段时间里没有活动）的流，将标志为 true 的流的标志也置为 false。
    unsigned scan_headEnd_matched, scan_uaBegin_matched, scan_uaEnd_matched;      // 记录现在已经匹配了多少个字节，由 __rkpStream_scan 设置，但可以由其它过程置零
    unsigned char *scan_uaBegin_p, *scan_uaEnd_p;       // 记录扫描的一些结果，由 __rkpStream_scan 设置，但可以由其它过程置零
    struct rkpMap* map;
    struct rkpStream *prev, *next;
};

struct rkpStream* rkpStream_new(const struct rkpPacket*);
void rkpStream_delete(struct rkpStream*);

bool rkpStream_belongTo(const struct rkpStream*, const struct rkpPacket*);      // 判断一个数据包是否属于一个流
unsigned rkpStream_execute(struct rkpStream*, struct rkpPacket*);               // 已知一个数据包属于这个流后，处理这个数据包

int32_t __rkpStream_seq_desired(const struct rkpStream*);                 // 返回 buff_scan 中最后一个数据包的后继的第一个字节的相对序列号

void __rkpStream_scan(struct rkpStream*, struct rkpPacket*);    // 对一个最新的包进行扫描
void __rkpStream_reset(struct rkpStream*);                      // 重置扫描进度，包括将 buff_scan 中的包全部发出
void __rkpStream_modify(struct rkpStream*);                     // 在收集到完整的 ua 后，对 ua 进行修改

struct rkpStream* rkpStream_new(const struct rkpPacket* rkpp)
{
    struct rkpStream* rkps;
    if(debug)
        printk("rkpStream_new\n");
    rkps = (struct rkpStream*)rkpMalloc(sizeof(struct rkpStream));
    if(rkps == 0)
        return 0;
    rkps -> status = __rkpStream_sniffing_uaBegin;
    memcpy(rkps -> id, rkpp -> lid, 3 * sizeof(u_int32_t));
    rkps -> buff_scan = rkps -> buff_disordered = 0;
    rkps -> seq_offset = rkpPacket_seq(rkpp, 0);
    rkps -> active = true;
    rkps -> scan_headEnd_matched = rkps -> scan_uaBegin_matched = rkps -> scan_uaEnd_matched = 0;
    rkps -> scan_uaBegin_p = rkps -> scan_uaEnd_p = 0;
    rkps -> map = 0;
    rkps -> prev = rkps -> next = 0;
    return rkps;
}
void rkpStream_delete(struct rkpStream* rkps)
{
    struct rkpPacket* rkpp;
    if(debug)
        printk("rkpStream_delete\n");
    rkpPacket_deletel(&rkps -> buff_scan);
    rkpPacket_deletel(&rkps -> buff_disordered);
    rkpFree(rkps);
}

bool rkpStream_belongTo(const struct rkpStream* rkps, const struct rkpPacket* rkpp)
{
    return memcmp(rkps -> id, rkpp -> lid, 3 * sizeof(u_int32_t)) == 0;
}
unsigned rkpStream_execute(struct rkpStream* rkps, struct rkpPacket* rkpp)
// 不要害怕麻烦，咱们把每一种情况都慢慢写一遍。
// 以下假定：包是客户端发到服务端的，并且带有应用层数据
{
    if(debug)
        printk("rkp-ua: rkpStream_execute start, judging...\n");

    // 肯定需要更新活动情况
    rkps -> active = true;
    
    // 接下来从小到大考虑数据包的序列号的几种情况
    // 已经发出的数据包，使用已有的映射修改
    if(rkpPacket_seq(rkpp, rkps -> seq_offset) < 0)
    {
        if(debug)
            printk("\tThe packet is re-transforming or has been modified, return NF_ACCEPT.\n");
        if(debug && rkpp -> skb -> mark & 0x10)
            printk("\tThe packet seems has been modified.\n");
        return NF_ACCEPT;
    }
    // 已经放到 buff_scan 中的数据包，丢弃
    if(rkpPacket_seq(rkpp, rkps -> seq_offset) < __rkpStream_seq_desired(rkps))
    {
        if(debug)
            printk("\tThe packet with same seq has been captured, return NF_DROP.\n");
        return NF_DROP;
    }
    // 恰好是 buff_scan 的后继数据包，这种情况比较麻烦，写到最后
    // 乱序导致还没接收到前继的数据包，放到 buff_disordered
    if(rkpPacket_seq(rkpp, rkps -> seq_offset) > __rkpStream_seq_desired(rkps))
    {
        if(debug)
            printk("\tThe packet is disordered, return NF_STOLEN.\n");
        __rkpStream_insert_auto(rkps, &rkps -> buff_disordered, rkpp);
        return NF_STOLEN;
    }

    // 接下来是恰好是 buff_scan 的后继数据包的情况，先分状态讨论，再一起考虑 buff_disordered 中的包
    // if(rkpPacket_seq(rkpp, rkps -> seq_offset) == __rkpStream_seq_desired(rkps))
    if(true)
    {
        // 因为一会儿可能还需要统一考虑 buff_disordered 中的包，因此不直接 return，将需要的返回值写到这里，最后再 return
        unsigned rtn;

        if(debug)
            printk("\tThe packet is desired one, further judging.\n");

        // 接下来分析几种情况
        //      * sniffing_uaBegin 状态下，先扫描这个数据包，再看情况处理
        //        需要考虑的方面有：
        //          * 是否扫描到了 uaBegin，通过 uaBegin_matched 是否与 str_uaBegin 长度相等判断
        //          * 在扫描到了 uaBegin 的前提下，是否得到了 ua 的开头位置。这是因为，可能一个数据包的结尾恰好是 `User-Agent: `，结果扫描到了 uaBegin 但是 ua 的开头在下一个数据包。通过 uaBegin_p 是否为非零值判断
        //          * 在扫描到了 uaBegin 和 ua 开头位置的前提下，是否扫描到了 uaEnd，通过 uaEnd_matched 是否与 str_uaEnd 长度相等判断
        //          * 在没有扫描到 uaBegin 的前提下，是否扫描到了 headEnd，通过 headEnd_matched 是否与 str_headEnd 长度相等判断；无需区分扫描到
        //            uaBegin 的各种情况中，扫描到 headEnd 与没有扫描到 headEnd 的情况，因为如果扫描到 headEnd，必然扫描到 ua 开头位置、uaEnd；分别考虑
        //            是否有 psh 的两对情况，得到的处理方法相同
        //          * 是否有 psh
        //        这些方面可能的组合（包括一些标准的 HTTP 协议不应该出现的组合）和处理办法为：
        //          1. 什么都没有扫描到，没有 psh。更新 seq_offset，返回 NF_ACCEPT。
        //          2. 什么都没有扫描到，有 psh。重置，更新 seq_offset，返回 NF_ACCEPT。
        //          3. 扫描到了 headEnd（其它都没有扫描到，下同），没有 psh。重置，状态切换为 waiting，更新 seq_offset，返回 NF_ACCEPT。
        //          4. 扫描到了 headEnd，有 psh。重置，更新 seq_offset，返回 NF_ACCEPT。
        //          5. 扫描到了 uaBegin，没有 psh。状态切换为 sniffing_uaEnd，更新 seq_offset，返回 NF_ACCEPT。
        //          6. 扫描到了 uaBegin，有 psh。发出警告，重置，更新 seq_offset，返回 NF_ACCEPT。
        //          7. 扫描到了 uaBegin、ua 开头位置，没有 psh。保留数据包，状态切换为 sniffing_uaEnd，返回 NF_STOLEN。
        //          8. 扫描到了 uaBegin、ua 开头位置，有 psh。发出警告，重置，更新 seq_offset，返回 NF_ACCEPT。
        //          9. 扫描到了 uaBegin、ua 开头位置、uaEnd，没有 psh。修改数据包，重置，状态切换为 waiting，更新 seq_offset，返回 NF_ACCEPT。
        //          10. 扫描到了 uaBegin、ua 开头位置、uaEnd，有 psh。修改数据包，重置，更新 seq_offset，返回 NF_ACCEPT。
        //        上面的情况中，有些情况的处置方法是类似的，因此可以合并；但为了整齐，在写代码时还是一个一个写出。
        //      * sniffing_uaEnd 状态下，如果之前没有扫描到 ua 开头位置，需要先将这个数据包的应用层起始位置作为 ua 开头位置，再扫描数据包，然后再分情况处理。
        //        需要考虑的方面有（这时 uaBegin 和 ua 开头位置一定已经扫描到，并且 headEnd 是否扫描到不影响结果）：
        //          * 是否扫描到了 uaEnd，判断方法同上
        //          * 在没有扫描到 uaEnd 的前提下，算上这个数据包，是否达到了预估的 ua 最大长度
        //          * 是否有 psh
        //        可能的组合和处理办法为：
        //          1. 没有扫描到 uaEnd，不到最大长度，没有 psh。保留数据包，返回 NF_STOLEN。
        //          2. 没有扫描到 uaEnd，不到最大长度，有 psh。发出警告，重置，状态切换为 sniffing_uaBegin，更新 seq_offset，返回 NF_ACCEPT。
        //          3. 没有扫描到 uaEnd，到最大长度，没有 psh。发出警告（ua 最大长度可能太小），重置，状态切换为 waiting，更新 seq_offset，返回 NF_ACCEPT。
        //          4. 没有扫描到 uaEnd，到最大长度，有 psh。发出警告，重置，状态切换为 sniffing_uaBegin，更新 seq_offset，返回 NF_ACCEPT。
        //          5. 扫描到 uaEnd，没有 psh。修改数据包，重置，状态切换为 waiting，更新 seq_offset，返回 NF_ACCEPT。
        //          6. 扫描到 uaEnd，有 psh。修改数据包，重置，状态切换为 sniffing_uaBegin，更新 seq_offset，返回 NF_ACCEPT。
        //      * waiting 状态下，如果有 psh，则将状态切换为 sniffing_uaBegin，否则不切换；然后更新 seq_offset，返回 NF_ACCEPT 即可。

        if(rkps -> status == __rkpStream_sniffing_uaBegin)
        {
            if(debug)
                printk("\t\tsniffing_uaBegin\n");
            __rkpStream_scan(rkps, rkpp);
            if(debug)
            {
                if(rkps -> scan_uaBegin_matched == strlen(str_uaBegin))
                    printk("\t\tuaBegin_matched.\n");
                if(rkps -> scan_uaBegin_p != 0)
                    printk("\t\tuaBegin_p matched.\n");
                if(rkps -> scan_uaEnd_matched == strlen(str_uaEnd))
                    printk("\t\tuaEnd_matched.\n");
                if(rkps -> scan_headEnd_matched == strlen(str_headEnd))
                    printk("\t\theadEnd_matched.\n");
                if(rkpPacket_psh(rkpp))
                    printk("\t\tpsh.\n");
            }
            if(rkps -> scan_uaBegin_matched < strlen(str_uaBegin))
                if(rkps -> scan_headEnd_matched < strlen(str_headEnd))
                    if(!rkpPacket_psh(rkpp))
                    {
                        rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                        rtn = NF_ACCEPT;
                    }
                    else
                    {
                        __rkpStream_reset(rkps);
                        rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                        rtn = NF_ACCEPT;
                    }
                else
                    if(!rkpPacket_psh(rkpp))
                    {
                        __rkpStream_reset(rkps);
                        rkps -> status = __rkpStream_waiting;
                        rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                        rtn = NF_ACCEPT;
                    }
                    else
                    {
                        __rkpStream_reset(rkps);
                        rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                        rtn = NF_ACCEPT;
                    }
            else
                if(rkps -> scan_uaBegin_p == 0)
                    if(!rkpPacket_psh(rkpp))
                    {
                        rkps -> status = __rkpStream_sniffing_uaEnd;
                        rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                        rtn = NF_ACCEPT;
                    }
                    else
                    {
                        if(verbose)
                            printk("half of ua found before psh.\n");
                        __rkpStream_reset(rkps);
                        rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                        rtn = NF_ACCEPT;
                    }
                else
                    if(rkps -> scan_uaEnd_matched < strlen(str_uaEnd))
                        if(!rkpPacket_psh(rkpp))
                        {
                            __rkpStream_insert_end(rkps, &rkps -> buff_scan, rkpp);
                            rkps -> status = __rkpStream_sniffing_uaEnd;
                            rtn = NF_STOLEN;
                        }
                        else
                        {
                            if(verbose)
                                printk("half of ua found before psh.\n");
                            __rkpStream_reset(rkps);
                            rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                            rtn = NF_ACCEPT;
                        }
                    else
                        if(!rkpPacket_psh(rkpp))
                        {
                            __rkpStream_insert_end(rkps, &rkps -> buff_scan, rkpp);
                            __rkpStream_modify(rkps);
                            __rkpStream_pop_end(rkps, &rkps -> buff_scan);
                            __rkpStream_reset(rkps);
                            rkps -> status = __rkpStream_waiting;
                            rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                            rtn = NF_ACCEPT;
                        }
                        else
                        {
                            __rkpStream_insert_end(rkps, &rkps -> buff_scan, rkpp);
                            __rkpStream_modify(rkps);
                            __rkpStream_pop_end(rkps, &rkps -> buff_scan);
                            __rkpStream_reset(rkps);
                            rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                            rtn = NF_ACCEPT;
                        }
        }
        else if(rkps -> status == __rkpStream_sniffing_uaEnd)
        {
            if(debug)
                printk("\t\tsniffing_uaEnd\n");
            if(rkps -> scan_uaBegin_p == 0)
                rkps -> scan_uaBegin_p = rkpPacket_appBegin(rkpp);
            __rkpStream_scan(rkps, rkpp);
            if(debug)
            {
                if(rkps -> scan_uaBegin_matched == strlen(str_uaBegin))
                    printk("\t\tuaBegin_matched.\n");
                if(rkps -> scan_uaBegin_p != 0)
                    printk("\t\tuaBegin_p matched.\n");
                if(rkps -> scan_uaEnd_matched == strlen(str_uaEnd))
                    printk("\t\tuaEnd_matched.\n");
                if(rkps -> scan_headEnd_matched == strlen(str_headEnd))
                    printk("\t\theadEnd_matched.\n");
                if(rkpPacket_psh(rkpp))
                    printk("\t\tpsh.\n");
            }
            if(rkps -> scan_uaEnd_matched < strlen(str_uaEnd))
                if(__rkpStream_num(rkps, rkps -> buff_scan) + 1 < len_ua)
                    if(!rkpPacket_psh(rkpp))
                    {
                        __rkpStream_insert_end(rkps, &rkps -> buff_scan, rkpp);
                        rtn = NF_STOLEN;
                    }
                    else
                    {
                        if(verbose)
                            printk("half of ua found before psh.\n");
                        __rkpStream_reset(rkps);
                        rkps -> status = __rkpStream_sniffing_uaBegin;
                        rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                        rtn = NF_ACCEPT;
                    }
                else
                    if(!rkpPacket_psh(rkpp))
                    {
                        if(verbose)
                            printk("len_ua=%d maybe too small.\n", len_ua);
                        __rkpStream_reset(rkps);
                        rkps -> status = __rkpStream_waiting;
                        rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                        rtn = NF_ACCEPT;
                    }
                    else
                    {
                        if(verbose)
                            printk("half of ua found before psh.\n");
                        __rkpStream_reset(rkps);
                        rkps -> status = __rkpStream_sniffing_uaBegin;
                        rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                        rtn = NF_ACCEPT;
                    }
            else
                if(!rkpPacket_psh(rkpp))
                {
                    __rkpStream_insert_end(rkps, &rkps -> buff_scan, rkpp);
                    __rkpStream_modify(rkps);
                    __rkpStream_pop_end(rkps, &rkps -> buff_scan);
                    __rkpStream_reset(rkps);
                    rkps -> status = __rkpStream_waiting;
                    rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                    rtn = NF_ACCEPT;
                }
                else
                {
                    __rkpStream_insert_end(rkps, &rkps -> buff_scan, rkpp);
                    __rkpStream_modify(rkps);
                    __rkpStream_pop_end(rkps, &rkps -> buff_scan);
                    __rkpStream_reset(rkps);
                    rkps -> status = __rkpStream_sniffing_uaBegin;
                    rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                    rtn = NF_ACCEPT;
                }
        }
        // else if(rkps -> status == __rkpStream_waiting)
        else
        {
            if(debug)
            {
                printk("\t\tsniffing_uaBegin\n");
                if(rkpPacket_psh(rkpp))
                    printk("\t\tpsh.\n");
            }
            if(rkpPacket_psh(rkpp))
                rkps -> status = __rkpStream_sniffing_uaBegin;
            rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
            rtn = NF_ACCEPT;
        }

        // 接下来考虑乱序的包
        while(rkps -> buff_disordered != 0)
        {
            // 序列号是已经发出去的，丢弃
            if(rkpPacket_seq(rkps -> buff_disordered, rkps -> seq_offset) < __rkpStream_seq_desired(rkps))
            {
                if(debug)
                    printk("\tdrop an disordered packet.\n");
                __rkpStream_pop_begin(rkps, &rkps -> buff_disordered);
            }
            // 如果序列号过大，结束循环
            else if(rkpPacket_seq(rkps -> buff_disordered, rkps -> seq_offset) > __rkpStream_seq_desired(rkps))
                break;
            // 如果序列号恰好，把它从链表中取出，然后像刚刚抓到的包那样去执行
            else
            {
                // 将包从链表中取出
                struct rkpPacket* rkpp2;
                unsigned rtn;
                if(debug)
                    printk("\texecute a disordered packet.\n");
                rkpp2 = __rkpStream_pop_begin(rkps, &rkps -> buff_disordered);
                rtn = rkpStream_execute(rkps, rkpp2);
                if(debug)
                {
                    if(rtn == NF_ACCEPT)
                        printk("\t\treturn NF_ACCEPT.\n");
                    else if(rtn == NF_DROP)
                        printk("\t\treturn NF_DROP.\n");
                    else if(rtn == NF_STOLEN)
                        printk("\t\treturn NF_STOLEN.\n");
                }
                if(rtn == NF_ACCEPT)
                    rkpPacket_send(rkpp2);
                else if(rtn == NF_DROP)
                    rkpPacket_drop(rkpp2);
                else if(rtn == NF_STOLEN);
            }
        }
        
        if(debug)
        {
            if(rtn == NF_ACCEPT)
                printk("\treturn NF_ACCEPT.\n");
            else if(rtn == NF_DROP)
                printk("\treturn NF_DROP.\n");
            else if(rtn == NF_STOLEN)
                printk("\treturn NF_STOLEN.\n");
        }
        return rtn;
    }
}

int32_t __rkpStream_seq_desired(const struct rkpStream* rkps)
{
    struct rkpPacket* rkpp = rkps -> buff_scan;
    if(rkpp == 0)
        return 0;
    else
        for(; ; rkpp = rkpp -> next)
            if(rkpp -> next == 0)
                return rkpPacket_seq(rkpp, rkps -> seq_offset) + rkpPacket_appLen(rkpp);
    
}

void __rkpStream_scan(struct rkpStream* rkps, struct rkpPacket* rkpp)
{
    unsigned char* p;
    // 需要匹配的量包括：headEnd、uaBegin、uaEnd。分为两个阶段。
    // 第一个阶段是 uaBegin 没有匹配完的阶段，这时尝试匹配 uaBegin 和 headEnd。
    // 如果匹配完 headEnd，不进入下一阶段而结束；如果匹配完 uaBegin，进入下一阶段，这一阶段只匹配 uaEnd
    for(p = rkpPacket_appBegin(rkpp); p != rkpPacket_appEnd(rkpp); p++)
    {
        if(rkps -> scan_uaBegin_matched < strlen(str_uaBegin))
        {
            if(*p == str_uaBegin[rkps -> scan_uaBegin_matched])
            {
                rkps -> scan_uaBegin_matched++;
                if(rkps -> scan_uaBegin_matched == strlen(str_uaBegin))
                {
                    if(p + 1 != rkpPacket_appEnd(rkpp))
                        rkps -> scan_uaBegin_p = p + 1;
                    continue;
                }
            }
            else
                rkps -> scan_uaBegin_matched = 0;
            if(*p == str_headEnd[rkps -> scan_headEnd_matched])
            {
                rkps -> scan_headEnd_matched++;
                if(rkps -> scan_headEnd_matched == strlen(str_headEnd))
                    return;
            }
            else
                rkps -> scan_headEnd_matched = 0;
        }
        else
        {
            if(*p == str_uaEnd[rkps -> scan_uaEnd_matched])
            {
                rkps -> scan_uaEnd_matched++;
                if(rkps -> scan_uaEnd_matched == strlen(str_uaEnd))
                {
                    int offset = p + 1 - rkpPacket_appBegin(rkpp);
                    // str_uaEnd 的末尾在现在的包中的偏移。如果小于等于 str_uaEnd 的长度，说明 ua 的实际结尾在上一个数据包；否则，在这个数据包。
                    if(offset <= strlen(str_uaEnd))
                    {
                        struct rkpPacket* i = rkps -> buff_scan;
                        while(i -> next != 0)
                            i = i -> next;
                        rkps -> scan_uaEnd_p = rkpPacket_appEnd(i) - (strlen(str_uaEnd) - offset);
                    }
                    else
                        rkps -> scan_uaEnd_p = p + 1 - strlen(str_uaEnd);
                    return;
                }
            }
            else
                rkps -> scan_uaEnd_matched = 0;
        }
    }
}
void __rkpStream_reset(struct rkpStream* rkps)
{
    struct rkpPacket* i;
    rkps -> scan_headEnd_matched = rkps -> scan_uaBegin_matched = rkps -> scan_uaEnd_matched = 0;
    rkps -> scan_uaBegin_p = rkps -> scan_uaEnd_p = 0;
    for(i = rkps -> buff_scan; i != 0;)
    {
        struct rkpPacket* j = i -> next;
        rkpPacket_send(i);
        i = j;
    }
    rkps -> buff_scan = 0;
}
void __rkpStream_modify(struct rkpStream* rkps)
{
    unsigned char* p;
    struct rkpPacket* rkpp;
    unsigned replaced;

    // 匹配需要保留的 ua
    if(n_str_preserve > 0)
    {
        unsigned* keyword_matched = (unsigned*)rkpMalloc(n_str_preserve * sizeof(unsigned));
        memset(keyword_matched, 0, n_str_preserve * sizeof(unsigned));
        p = rkps -> scan_uaBegin_p;
        rkpp = rkps -> buff_scan;
        while(p != rkps -> scan_uaEnd_p)
        {
            unsigned i;
            for(i = 0; i < n_str_preserve; i++)
            {
                if(*p == str_preserve[i][keyword_matched[i]])
                    keyword_matched[i]++;
                else
                    keyword_matched[i] = 0;
                if(keyword_matched[i] == strlen(str_preserve[i]))
                {
                    rkpFree(keyword_matched);
                    return;
                }
            }
            p++;
            if(p == rkpPacket_appEnd(rkpp))
            {
                rkpp = rkpp -> next;
                if(rkpp == 0)
                    break;
                else
                    p = rkpPacket_appBegin(rkpp);
            }
        }
        rkpFree(keyword_matched);
    }

    // 执行到这里，说明不是需要保留的 ua，接下来替换字符串
    p = rkps -> scan_uaBegin_p;
    rkpp = rkps -> buff_scan;
    replaced = 0;
    while(p != rkps -> scan_uaEnd_p)
    {
        if(replaced < strlen(str_uaRkp))
        {
            *p = str_uaRkp[replaced];
            replaced++;
        }
        else
            *p = ' ';
        p++;
        if(p == rkpPacket_appEnd(rkpp))
        {
            rkpp = rkpp -> next;
            if(rkpp == 0)
                break;
            else
                p = rkpPacket_appBegin(rkpp);
        }
    }

    // 计算校验和
    rkpp = rkps -> buff_scan;
    while(rkpp != 0)
    {
        rkpPacket_csum(rkpp);
        rkpp = rkpp -> next;
    }
}
