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
#include <asm/limits.h>
#include <linux/time.h>

const unsigned char* str_ua_start = "User-Agent: ";
const unsigned char* str_ua_end = "\r\n";
const unsigned char* str_head_end = "\r\n\r\n";
const unsigned char str_ua_rkp[7];

time_t now()
{
    struct timespec* ts;
    getnstimeofday(ts);
    return ts -> tv_sec;
}
