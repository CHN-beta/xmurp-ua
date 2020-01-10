#pragma once
#include "common.h"
#include "rkpPacket.h"

struct rkpMap
// 以相对序列号记录应用层数据中需要修改的部分的位置，提供修改的函数
{
    int32_t begin, length;      // begin 为绝对
    struct rkpMap *prev, *next;
};

struct rkpMap* rkpMap_new(int32_t, int32_t);
void rkpMap_delete(struct rkpMap*);

unsigned char __rkpMap_map(const struct rkpMap*, int32_t);      // 返回某个序列号对应的映射后的值。假定参数是合法的。第一个参数实际上没有用。
void rkpMap_modify(const struct rkpMap*, struct rkpPacket**, int32_t);      // 对一列序列号连续且递增的包进行修改

void rkpMap_insert_begin(struct rkpMap**, struct rkpMap*);      // 在开头位置插入一个映射
void rkpMap_insert_end(struct rkpMap**, struct rkpMap*);
void rkpMap_refresh(struct rkpMap**, int32_t, int32_t);                  // 对于一列序列号递增的映射，

struct rkpMap* rkpMap_new(int32_t begin, int32_t length)
{
    struct rkpMap* rkpm = (struct rkpMap*)rkpMalloc(sizeof(struct rkpMap));
    if(rkpm == 0)
        return 0;
    rkpm -> begin = begin;
    rkpm -> length = length;
    rkpm -> prev = rkpm -> next = 0;
    return rkpm;
}
void rkpMap_delete(struct rkpMap* rkpm)
{
    rkpFree(rkpm);
}

unsigned char __rkpMap_map(const struct rkpMap* rkpm, int32_t seq)
{
    int32_t offset = seq - rkpm -> begin;
    if(offset < strlen(str_uaRkp))
        return str_uaRkp[offset];
    else 
        return ' ';
}
void rkpMap_modify(const struct rkpMap* rkpm, struct rkpPacket** rkppl, int32_t doff)
{
    int32_t seql = rkpPacket_seq(rkpp, doff), seqr = seql + rkpPacket_appLen(rkpp);
    unsigned char *pl = rkpPacket_appBegin(rkpp), *pr = rkpPacket_appEnd(rkpp);
    if(seql >= rkpm -> begin + rkpm -> length || seqr <= rkpm -> begin)
        return;
    if(seqr > rkpm -> begin + rkpm -> length)
    {
        unsigned doff = seqr - (rkpm -> begin + rkpm -> length);
        seqr -= doff;
        pr -= doff;
    }
    if(seql < rkpm -> begin)
    {
        unsigned doff = rkpm -> begin - seql;
        seql += doff;
        pl += doff;
    }
    for(;seql < seqr; seql++, pl++)
        *pl = __rkpMap_map(rkpm, seql);
}
void rkpMap_move(struct rkpMap* rkpm, int32_t doff)
{
    rkpm -> begin += doff;
}

void rkpMap_insert_begin(struct rkpMap** rkpml, struct rkpMap* rkpm)
{
    rkpm -> next = *rkpml;
    rkpm -> prev = 0;
    *rkpml = rkpm;
    if(rkpm -> next != 0)
        rkpm -> next -> prev = rkpm;
}
void rkpMap_refresh(struct rkpMap** rkpml, int32_t seq)
{
    struct rkpMap* rkpm = *rkpml;
    while(rkpm != 0)
    {
        if(rkpm -> begin + rkpm -> length <= seq)
        {
            struct rkpMap* rkpm2 = rkpm -> next;
            if(rkpm -> prev != 0)
                rkpm -> prev -> next = rkpm -> next;
            if(rkpm -> next != 0)
                rkpm -> next -> prev = rkpm -> prev;
            rkpMap_delete(rkpm);
            rkpm = rkpm2;
        }
        else
            rkpm = rkpm -> next;
    }
}