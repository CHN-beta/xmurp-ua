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

const char* str_ua = "User-Agent: ";
const char* str_end = "\r\n\r\n";
const char* str_win = "Windows NT";

u_int32_t mark_capture = 0x100;
module_param(mark_capture, uint, 0);
u_int32_t mark_request = 0x200;
module_param(mark_request, uint, 0);
u_int32_t mark_first = 0x400;
module_param(mark_first, uint, 0);
u_int32_t mark_winPreserve = 0x800;
module_param(mark_winPreserve, uint, 0);

