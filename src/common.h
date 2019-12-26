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

const static unsigned char* str_ua_begin = "User-Agent: ";
const static unsigned char* str_ua_end = "\r\n";
const static unsigned char* str_head_end = "\r\n\r\n";
static unsigned char str_ua_rkp[16];

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
