#pragma once
#include "common.h"

struct rkpMap
// 以相对序列号记录应用层数据中需要修改的部分的位置，提供修改的函数
{
    int32_t begin, length;                  // begin 为绝对序列号
    // int32_t &seq_offset = beign;         // 需要一个差不多的数值作为偏移来计算序列号谁先谁后的问题，这个偏移取为 begin
    struct rkpMap *prev, *next;
};

struct rkpMap* rkpMap_new(int32_t, int32_t);                    // 两个参数分别为起始和终止绝对序列号
void rkpMap_delete(struct rkpMap*);

unsigned char __rkpMap_map(const struct rkpMap*, int32_t);      // 返回某个序列号对应的映射后的值。假定参数是合法的。这里的参数是相对序列号
void rkpMap_modify(struct rkpMap**, struct rkpPacket**);  // 对一列序列号连续且递增的包进行修改

void rkpMap_insert_begin(struct rkpMap**, struct rkpMap*);      // 在开头位置插入一个映射
void rkpMap_insert_end(struct rkpMap**, struct rkpMap*);
void rkpMap_refresh(struct rkpMap**, int32_t);                  // 对于一列序列号递增的映射，删除已经回应的映射

struct rkpMap* rkpMap_new(int32_t seql, int32_t seqr)
{
    struct rkpMap* rkpm = (struct rkpMap*)rkpMalloc(sizeof(struct rkpMap));
    if(rkpm == 0)
        return 0;
    rkpm -> begin = seql;
    rkpm -> length = seqr - seql;
    rkpm -> prev = rkpm -> next = 0;
    return rkpm;
}
void rkpMap_delete(struct rkpMap* rkpm)
{
    rkpFree(rkpm);
}

unsigned char __rkpMap_map(const struct rkpMap* rkpm, int32_t seq)
{
    if(seq < strlen(str_uaRkp))
        return str_uaRkp[seq];
    else 
        return ' ';
}
void rkpMap_modify(struct rkpMap** rkpml, struct rkpPacket** rkppl)
{
    const struct rkpMap* rkpm;
    for(rkpm = *rkpml; rkpm != 0; rkpm = rkpm -> next)
    {
        struct rkpPacket* rkpp;
        unsigned char* p = 0;
        int32_t seq;

        // 尝试确定第一个需要修改的包以及需要修改的开始处
        for(rkpp = *rkppl; rkpp != 0; rkpp = rkpp -> next)
            if(rkpPacket_seq(rkpp, rkpm -> begin) + rkpPacket_appLen(rkpp) > 0)
                break;
        if(rkpp == 0)
            break;
        if(rkpPacket_seq(rkpp, rkpm -> begin) <= 0)
        {
            p = rkpPacket_appBegin(rkpp) - rkpPacket_seq(rkpp, rkpm -> begin);
            seq = 0;
        }
        else    // p 会在稍后被设置到包的开头
            seq = rkpPacket_seq(rkpp, rkpm -> begin);
        
        // 开始修改
        for(; rkpp != 0; rkpp = rkpp -> next)
        {
            if(seq != 0)
                p = rkpPacket_appBegin(rkpp);
            for(; p != rkpPacket_appEnd(rkpp) && seq < rkpm -> length; p++, seq++)
                *p = __rkpMap_map(rkpm, seq);
            rkpPacket_csum(rkpp);
            if(seq == rkpm -> length)
                break;
        }
    }
}

void rkpMap_insert_begin(struct rkpMap** rkpml, struct rkpMap* rkpm)
{
    rkpm -> next = *rkpml;
    *rkpml = rkpm;
    if(rkpm -> next != 0)
        rkpm -> next -> prev = rkpm;
}
void rkpMap_insert_end(struct rkpMap** rkpml, struct rkpMap* rkpm)
{
    if(*rkpml == 0)
        *rkpml = rkpm;
    else
    {
        struct rkpMap* rkpm2;
        for(rkpm2 = *rkpml; rkpm2 -> next != 0; rkpm2 = rkpm2 -> next);
        rkpm2 -> next = rkpm;
        rkpm -> prev = rkpm2;
    }
}
void rkpMap_refresh(struct rkpMap** rkpml, int32_t seq)
{
    struct rkpMap *rkpm1, *rkpm2, *rkpm3;
    // 找到第一个不用删除的映射
    for(rkpm1 = *rkpml; rkpm1 != 0; rkpm1 = rkpm1 -> next)
        // if(rkpm -> begin + rkpm -> length > seq)        需要避免绝对值很大的负数小于绝对值很大的正数的情况
        if((int32_t)(seq - rkpm1 -> begin) - rkpm1 -> length < 0)
            break;
    // 将这个映射之前的所有映射都删除
    for(rkpm2 = *rkpml; rkpm2 != rkpm1; rkpm2 = rkpm3)
    {
        rkpm3 = rkpm2 -> next;
        rkpMap_delete(rkpm2);
    }
    // 修改一些指针
    if(rkpm1 != 0)
        rkpm1 -> prev = 0;
    *rkpml = rkpm1;
}