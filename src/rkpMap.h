#pragma once
#include "common.h"
#include "rkpPacket.h"

struct rkpMap
{
    int32_t left, right;
    struct rkpMap *prev, *next;
};

struct rkpMap* rkpMap_new(int32_t, int32_t);
void rkpMap_delete(int32_t, int32_t);

unsigned char rkpMap_map(int32_t);
void rkpMap_modify(struct rkpPacket*);
