#pragma once
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
#include <linux/random.h>
#include <linux/moduleparam.h>
#include <linux/time.h>
#include <linux/mutex.h>

typedef _Bool bool;
#ifndef static_assert
    #define static_assert _Static_assert
#endif

const static unsigned char* str_uaBegin = "User-Agent: ";
const static unsigned char* str_uaEnd = "\r\n";
const static unsigned char* str_headEnd = "\r\n\r\n";
static unsigned char str_uaRkp[16];

void* rkpMalloc(unsigned size)
{
    void* p = kmalloc(size, GFP_NOWAIT);
    if(p == 0)
        printk("rkp-ua: malloc failed.\n");
    return p;
}
void rkpFree(void* p)
{
    kfree(p);
}
