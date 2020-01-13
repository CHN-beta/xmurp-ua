#pragma once
#include "common.h"

struct rkpStream
// 接管一个 TCP 流。
{
    enum
    {
        __rkpStream_sniffing_uaBegin,           // 正在寻找 http 头的结尾或者 ua 的开始，这时 buff_scan 中不应该有包
        __rkpStream_sniffing_uaEnd,             // 已经找到 ua，正在寻找它的结尾，buff_scan 中可能有包
        __rkpStream_waiting                     // 已经找到 ua 的结尾或者 http 头的结尾并且还没有 psh，接下来的包都直接放行
    } status;
    enum
    {
        __rkpStream_scan_noFound,               // 还没找到 ua 的开头
        __rkpStream_scan_uaBegin,               // 匹配到了 ua 开头，但是 ua 实际的开头在下个数据包
        __rkpStream_scan_uaRealBegin,           // 匹配到了 ua 开头，ua 实际的开头在这个数据包
        __rkpStream_scan_uaEnd,                 // 匹配到了 ua 的结尾，并且需要修改 ua
        __rkpStream_scan_uaGood,                // 匹配到了 ua 的结尾，但是不需要修改 ua
        __rkpStream_scan_headEnd                // 匹配到了 http 头部的结尾，没有发现 ua
    } scan_status;                              // 记录扫描结果，仅由 __rkpStream_scan 和 __rkpStream_reset 设置，由 rkpStream_execute 和 __rkpStream_scan 读取
    u_int32_t id[3];                            // 按顺序存储客户地址、服务地址、客户端口、服务端口，已经转换字节序
    struct rkpPacket *buff_scan, *buff_disordered;      // 分别存储准备扫描的、因乱序而提前收到的数据包，都按照序号排好了
    int32_t seq_offset;                         // 序列号的偏移。使得 buff_scan 中第一个字节的编号为零。在 rkpStream 中，序列号使用相对值；但在传给下一层时，使用绝对值
    bool active;                                // 是否仍然活动，流每次处理的时候会置为 true，每隔一段时间会删除标志为 false（说明它在这段时间里没有活动）的流，将标志为 true 的流的标志也置为 false。
    unsigned scan_headEnd_matched, scan_uaBegin_matched, scan_uaEnd_matched, *scan_uaPreserve_matched;
            // 记录现在已经匹配了多少个字节，仅由 __rkpStream_scan 和 __rkpStream_reset 使用
    uint32_t scan_uaBegin_seq, scan_uaEnd_seq;
            // 记录 ua 开头和结束的序列号，仅由 __rkpStream_scan、__rkpStream_reset 设置
    struct rkpMap* map;                         // 记录 ua 的位置，方便修改重传数据包，仅由 __rkpStream_modify 使用
    struct rkpStream *prev, *next;
};

struct rkpStream* rkpStream_new(const struct rkpPacket*);
void rkpStream_delete(struct rkpStream*);

bool rkpStream_belongTo(const struct rkpStream*, const struct rkpPacket*);      // 判断一个数据包是否属于一个流
unsigned rkpStream_execute(struct rkpStream*, struct rkpPacket*);               // 已知一个数据包属于这个流后，处理这个数据包

int32_t __rkpStream_seq_desired(const struct rkpStream*);                 // 返回 buff_scan 中最后一个数据包的后继的第一个字节的相对序列号

void __rkpStream_scan(struct rkpStream*, struct rkpPacket*);    // 对一个最新的包进行扫描
void __rkpStream_reset(struct rkpStream*);                      // 重置扫描进度，包括将 buff_scan 中的包全部发出

struct rkpStream* rkpStream_new(const struct rkpPacket* rkpp)
{
    struct rkpStream* rkps;
    if(debug)
        printk("rkpStream_new\n");
    rkps = (struct rkpStream*)rkpMalloc(sizeof(struct rkpStream) + sizeof(unsigned) * n_str_preserve);
    if(rkps == 0)
        return 0;
    rkps -> scan_uaPreserve_matched = (unsigned*)((void*)rkps + sizeof(struct rkpStream));
    rkps -> status = __rkpStream_sniffing_uaBegin;
    memcpy(rkps -> id, rkpp -> lid, 3 * sizeof(u_int32_t));
    rkps -> buff_scan = rkps -> buff_disordered = 0;
    rkps -> seq_offset = rkpPacket_seq(rkpp, 0);
    if(rkpPacket_syn(rkpp))
        rkps -> seq_offset++;
    rkps -> active = true;
    rkps -> map = 0;
    rkps -> prev = rkps -> next = 0;
    __rkpStream_reset(rkps);
    return rkps;
}
void rkpStream_delete(struct rkpStream* rkps)
{
    struct rkpMap* rkpm;
    if(debug)
        printk("rkpStream_delete\n");
    rkpPacket_deletel(&rkps -> buff_scan);
    rkpPacket_deletel(&rkps -> buff_disordered);
    for(rkpm = rkps -> map; rkpm != 0; rkpm = rkpm -> next)
        rkpMap_delete(rkpm);
    rkpFree(rkps);
}

bool rkpStream_belongTo(const struct rkpStream* rkps, const struct rkpPacket* rkpp)
{
    if(debug)
        printk("rkpStream_belongTo\n");
    return memcmp(rkps -> id, rkpp -> lid, 3 * sizeof(u_int32_t)) == 0;
}
unsigned rkpStream_execute(struct rkpStream* rkps, struct rkpPacket* rkpp)
// 不要害怕麻烦，咱们把每一种情况都慢慢写一遍。
{
    if(debug)
        printk("rkp-ua: rkpStream_execute start, judging %u ...\n", rkpPacket_seq(rkpp, 0));

    // 肯定需要更新活动情况
    rkps -> active = true;
    
    // 首先处理如果是 ack 的情况
    if(rkpp -> ack)
    {
        if(debug)
            printk("ack packet\n");
        rkpMap_refresh(&rkps -> map, rkpPacket_seqAck(rkpp, 0));
        return NF_ACCEPT;
    }

    // 其它情况，首先放掉所有没有应用层数据的包
    if(rkpPacket_appLen(rkpp) == 0)
    {
        if(debug)
            printk("empty packet\n");
        return NF_ACCEPT;
    }

    // 接下来从小到大考虑数据包的序列号的几种情况
    // 已经发出的数据包，使用已有的映射修改
    if(rkpPacket_seq(rkpp, rkps -> seq_offset) < 0)
    {
        if(debug)
            printk("\tThe packet is re-transforming or has been modified.\n");
        rkpMap_modify(&rkps -> map, &rkpp);
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
        rkpPacket_insert_auto(&rkps -> buff_disordered, rkpp, rkps -> seq_offset);
        return NF_STOLEN;
    }

    // 接下来是恰好是 buff_scan 的后继数据包的情况，先分状态讨论，再一起考虑 buff_disordered 中的包
    // if(rkpPacket_seq(rkpp, rkps -> seq_offset) == __rkpStream_seq_desired(rkps))
    if(true)
    {
        // 因为一会儿可能还需要统一考虑 buff_disordered 中的包，因此不直接 return，将需要的返回值写到这里，最后再 return
        unsigned rtn = NF_ACCEPT;

        if(debug)
            printk("\tThe packet is desired one, further judging.\n");

        // 接下来分析几种情况
        //      * sniffing_uaBegin 状态下，先扫描这个数据包，再看情况处理。需要考虑 scan_status 和是否有 psh。
        //          * 没有 psh 的情况：
        //              * noFound：更新 seq_offset，返回 NF_ACCEPT。
        //              * uaBegin：状态切换为 sniffing_uaEnd，更新 seq_offset，返回 NF_ACCEPT。
        //              * uaRealBegin：保留数据包，状态切换为 sniffing_uaEnd，返回 NF_STOLEN。
        //              * uaEnd：生成映射，修改数据包，重置扫描进度，状态切换为 waiting，更新 seq_offset，返回 NF_ACCEPT。
        //              * uaGood 或 headEnd：重置扫描进度，状态切换为 waiting，更新 seq_offset，返回 NF_ACCEPT。
        //          * 有 psh 的情况：
        //              * noFound、uaBegin、uaRealBegin、uaGood 或 headEnd：重置扫描进度，更新 seq_offset，返回 NF_ACCEPT。
        //              * uaEnd：生成映射，修改数据包，重置扫描进度，更新 seq_offset，返回 NF_ACCEPT。
        //      * sniffing_uaEnd 状态下，同样是先扫描数据包，然后再分情况处理。需要考虑 scan_status、是否有 psh 以及是否达到最大长度
        //          * 没有 psh 的情况：
        //              * uaBegin 或 uaRealBegin：如果到了最大长度，就发出警告（ua 最大长度可能太小），重置扫描进度，发出数据包，状态切换为 waiting，更新 seq_offset，返回 NF_ACCEPT；
        //                      否则，保留数据包，返回 NF_STOLEN。
        //              * uaEnd：生成映射，修改数据包，重置扫描进度，发出数据包，状态切换为 waiting，更新 seq_offset，返回 NF_ACCEPT。
        //              * uaGood：重置扫描进度，发出数据包，状态切换为 waiting，更新 seq_offset，返回 NF_ACCEPT。
        //          * 有 psh 的情况：
        //              * uaBegin、uaRealBegin 或 uaGood：重置扫描进度，发出数据包，状态切换为 sniffing_uaBegin，更新 seq_offset，返回 NF_ACCEPT。
        //              * uaEnd：生成映射，修改数据包，重置扫描进度，发出数据包，状态切换为 sniffing_uaBegin，更新 seq_offset，返回 NF_ACCEPT。
        //      * waiting 状态下，如果有 psh，则将状态切换为 sniffing_uaBegin，否则不切换；然后更新 seq_offset，返回 NF_ACCEPT 即可。

        if(rkps -> status == __rkpStream_sniffing_uaBegin)
        {
            if(debug)
                printk("\t\tsniffing_uaBegin\n");
            __rkpStream_scan(rkps, rkpp);
            if(debug)
            {
                if(rkps -> scan_status == __rkpStream_scan_noFound)
                    printk("\t\tnoFound\n");
                else if(rkps -> scan_status == __rkpStream_scan_uaBegin)
                    printk("\t\tuaBegin\n");
                else if(rkps -> scan_status == __rkpStream_scan_uaRealBegin)
                    printk("\t\tuaRealBegin\n");
                else if(rkps -> scan_status == __rkpStream_scan_uaEnd)
                    printk("\t\tuaEnd\n");
                else if(rkps -> scan_status == __rkpStream_scan_uaGood)
                    printk("\t\tuaGood\n");
                else if(rkps -> scan_status == __rkpStream_scan_headEnd)
                    printk("\t\theadEnd\n");
                if(rkpPacket_psh(rkpp))
                    printk("\t\tpsh\n");
            }
            if(!rkpPacket_psh(rkpp))
                switch (rkps -> scan_status)
                {
                case __rkpStream_scan_noFound:
                    rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                    rtn = NF_ACCEPT;
                    break;
                case __rkpStream_scan_uaBegin:
                    rkps -> status = __rkpStream_sniffing_uaEnd;
                    rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                    rtn = NF_ACCEPT;
                    break;
                case __rkpStream_scan_uaRealBegin:
                    rkpPacket_insert_end(&rkps -> buff_scan, rkpp);
                    rkps -> status = __rkpStream_sniffing_uaEnd;
                    rtn = NF_STOLEN;
                    break;
                case __rkpStream_scan_uaEnd:
                    rkpMap_insert_end(&rkps -> map, rkpMap_new(rkps -> scan_uaBegin_seq, rkps -> scan_uaEnd_seq));
                    rkpMap_modify(&rkps -> map, &rkpp);
                    __rkpStream_reset(rkps);
                    rkps -> status = __rkpStream_waiting;
                    rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                    rtn = NF_ACCEPT;
                    break;
                case __rkpStream_scan_uaGood:
                case __rkpStream_scan_headEnd:
                    __rkpStream_reset(rkps);
                    rkps -> status = __rkpStream_waiting;
                    rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                    rtn = NF_ACCEPT;
                }
            else
                switch (rkps -> scan_status)
                {
                case __rkpStream_scan_noFound:
                case __rkpStream_scan_uaBegin:
                case __rkpStream_scan_uaRealBegin:
                case __rkpStream_scan_uaGood:
                case __rkpStream_scan_headEnd:
                    __rkpStream_reset(rkps);
                    rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                    rtn = NF_ACCEPT;
                    break;
                case __rkpStream_scan_uaEnd:
                    rkpMap_insert_end(&rkps -> map, rkpMap_new(rkps -> scan_uaBegin_seq, rkps -> scan_uaEnd_seq));
                    rkpMap_modify(&rkps -> map, &rkpp);
                    __rkpStream_reset(rkps);
                    rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                    rtn = NF_ACCEPT;
                }
        }
        else if(rkps -> status == __rkpStream_sniffing_uaEnd)
        {
            if(debug)
                printk("\t\tsniffing_uaEnd\n");
            __rkpStream_scan(rkps, rkpp);
            if(debug)
            {
                if(rkps -> scan_status == __rkpStream_scan_noFound)
                    printk("\t\tnoFound\n");
                else if(rkps -> scan_status == __rkpStream_scan_uaBegin)
                    printk("\t\tuaBegin\n");
                else if(rkps -> scan_status == __rkpStream_scan_uaRealBegin)
                    printk("\t\tuaRealBegin\n");
                else if(rkps -> scan_status == __rkpStream_scan_uaEnd)
                    printk("\t\tuaEnd\n");
                else if(rkps -> scan_status == __rkpStream_scan_uaGood)
                    printk("\t\tuaGood\n");
                else if(rkps -> scan_status == __rkpStream_scan_headEnd)
                    printk("\t\theadEnd\n");
                if(rkpPacket_psh(rkpp))
                    printk("\t\tpsh\n");
            }
            if(!rkpPacket_psh(rkpp))
                switch (rkps -> scan_status)
                {
                case __rkpStream_scan_uaBegin:
                case __rkpStream_scan_uaRealBegin:
                    if(rkpPacket_num(&rkps -> buff_scan) + 1 == len_ua)
                    {
                        printk("warning: len_ua may be too short.\n");
                        __rkpStream_reset(rkps);
                        rkpPacket_sendl(&rkps -> buff_scan);
                        rkps -> status = __rkpStream_waiting;
                        rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                        rtn = NF_ACCEPT;
                    }
                    else
                    {
                        rkpPacket_insert_end(&rkps -> buff_scan, rkpp);
                        rtn = NF_STOLEN;
                    }
                    break;
                case __rkpStream_scan_uaEnd:
                    rkpMap_insert_end(&rkps -> map, rkpMap_new(rkps -> scan_uaBegin_seq, rkps -> scan_uaEnd_seq));
                    rkpMap_modify(&rkps -> map, &rkps -> buff_scan);
                    rkpMap_modify(&rkps -> map, &rkpp);
                    __rkpStream_reset(rkps);
                    rkpPacket_sendl(&rkps -> buff_scan);
                    rkps -> status = __rkpStream_waiting;
                    rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                    rtn = NF_ACCEPT;
                    break;
                case __rkpStream_scan_uaGood:
                    __rkpStream_reset(rkps);
                    rkpPacket_sendl(&rkps -> buff_scan);
                    rkps -> status = __rkpStream_waiting;
                    rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                    rtn = NF_ACCEPT;
                    break;
                case __rkpStream_scan_noFound:
                case __rkpStream_scan_headEnd:
                    break;
                }
            else
                switch (rkps -> scan_status)
                {
                case __rkpStream_scan_uaBegin:
                case __rkpStream_scan_uaRealBegin:
                case __rkpStream_scan_uaGood:
                    __rkpStream_reset(rkps);
                    rkpPacket_sendl(&rkps -> buff_scan);
                    rkps -> status = __rkpStream_sniffing_uaBegin;
                    rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                    rtn = NF_ACCEPT;
                    break;
                case __rkpStream_scan_uaEnd:
                    rkpMap_insert_end(&rkps -> map, rkpMap_new(rkps -> scan_uaBegin_seq, rkps -> scan_uaEnd_seq));
                    rkpMap_modify(&rkps -> map, &rkps -> buff_scan);
                    rkpMap_modify(&rkps -> map, &rkpp);
                    __rkpStream_reset(rkps);
                    rkpPacket_sendl(&rkps -> buff_scan);
                    rkps -> status = __rkpStream_sniffing_uaBegin;
                    rkpPacket_makeOffset(rkpp, &rkps -> seq_offset);
                    rtn = NF_ACCEPT;
                    break;
                case __rkpStream_scan_noFound:
                case __rkpStream_scan_headEnd:
                    break;
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
                rkpPacket_drop(rkpPacket_pop_begin(&rkps -> buff_disordered));
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
                rkpp2 = rkpPacket_pop_begin(&rkps -> buff_disordered);
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
    if(debug)
        printk("rkpStream_seq_desired\n");
    struct rkpPacket* rkpp = rkps -> buff_scan;
    if(rkpp == 0)
        return 0;
    else
    {
        for(; rkpp -> next != 0; rkpp = rkpp -> next);
        return rkpPacket_seq(rkpp, rkps -> seq_offset) + rkpPacket_appLen(rkpp);
    }
}

void __rkpStream_scan(struct rkpStream* rkps, struct rkpPacket* rkpp)
{
    unsigned char* p = rkpPacket_appBegin(rkpp);
    if(debug)
        printk("rkpStream_scan\n");

    // 需要匹配的字符串包括：headEnd、uaBegin、uaEnd、uaPreserve
    // 开始这个函数时，scan_status 只可能是 noFound、uaBegin 或 uaRealBegin（这两个可以无差别对待）
    //      * noFound：扫描 uaBegin、headEnd，当匹配到其中一个时停下来开始决策
    //          * uaBegin：如果已经到数据包末尾，则将状态设置为 uaBegin，写入 scan_uaBegin_seq，返回；否则，将状态设置为 uaRealBegin，写入 scan_uaBegin_seq，继续下个阶段的扫描
    //          * headEnd：将状态设置为 headEnd，返回
    //      * uaBegin 或 uaRealBegin：扫描 uaEnd、uaPreserve，匹配到其中一个时停下来开始决策
    //          * uaEnd：将状态设置为 uaEnd，设置 scan_uaEnd_seq，返回
    //          * uaPreserve：将状态设置为 uaGood，返回

    if(rkps -> scan_status == __rkpStream_scan_noFound)
        for(; p != rkpPacket_appEnd(rkpp); p++)
        {
            if(*p == str_uaBegin[rkps -> scan_uaBegin_matched])
            {
                rkps -> scan_uaBegin_matched++;
                if(rkps -> scan_uaBegin_matched == strlen(str_uaBegin))
                {
                    if(p + 1 == rkpPacket_appEnd(rkpp))
                        rkps -> scan_status = __rkpStream_scan_uaBegin;
                    else
                        rkps -> scan_status = __rkpStream_scan_uaRealBegin;
                    rkps -> scan_uaBegin_seq = rkpPacket_seq(rkpp, 0) + ((p + 1) - rkpPacket_appBegin(rkpp));
                    if(debug)
                        printk("uaBegin_seq %u\n", rkps -> scan_uaBegin_seq);
                    p++;
                    break;
                }
            }
            else
                rkps -> scan_uaBegin_matched = 0;
            if(*p == str_headEnd[rkps -> scan_headEnd_matched])
            {
                rkps -> scan_headEnd_matched++;
                if(rkps -> scan_headEnd_matched == strlen(str_headEnd))
                {
                    rkps -> scan_status = __rkpStream_scan_headEnd;
                    return;
                }
            }
            else
                rkps -> scan_headEnd_matched = 0;
        }

    if(rkps -> scan_status == __rkpStream_scan_uaBegin || rkps -> scan_status == __rkpStream_scan_uaRealBegin)
        for(; p != rkpPacket_appEnd(rkpp); p++)
        {
            unsigned i;
            if(*p == str_uaEnd[rkps -> scan_uaEnd_matched])
            {
                rkps -> scan_uaEnd_matched++;
                if(rkps -> scan_uaEnd_matched == strlen(str_uaEnd))
                {
                    rkps -> scan_status = __rkpStream_scan_uaEnd;
                    rkps -> scan_uaEnd_seq = rkpPacket_seq(rkpp, 0) + ((p + 1) - rkpPacket_appBegin(rkpp)) - strlen(str_uaEnd);
                    if(debug)
                        printk("uaEnd_seq %u\n", rkps -> scan_uaEnd_seq);
                    return;
                }
            }
            else
                rkps -> scan_uaEnd_matched = 0;
            for(i = 0; i < n_str_preserve; i++)
            {
                if(*p == str_preserve[i][rkps -> scan_uaPreserve_matched[i]])
                {
                    rkps -> scan_uaPreserve_matched[i]++;
                    if(rkps -> scan_uaPreserve_matched[i] == strlen(str_preserve[i]))
                    {
                        rkps -> scan_status = __rkpStream_scan_uaGood;
                        return;
                    }
                }
                else
                    rkps -> scan_uaPreserve_matched[i] = 0;
            }
        }
}
void __rkpStream_reset(struct rkpStream* rkps)
{
    if(debug)
        printk("rkpStream_reset\n");
    rkps -> scan_status = __rkpStream_scan_noFound;
    rkps -> scan_headEnd_matched = rkps -> scan_uaBegin_matched = rkps -> scan_uaEnd_matched = 0;
    memset(rkps -> scan_uaPreserve_matched, 0, sizeof(unsigned) * n_str_preserve);
}
