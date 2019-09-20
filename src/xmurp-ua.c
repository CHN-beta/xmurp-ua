#include <linux/module.h>
#include <linux/version.h>
#include <linux/kmod.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netdevice.h>
#include <linux/random.h>

static struct nf_hook_ops nfho;

enum char_scan_enum
{
	next,
	modified_and_next,
	scan_finish,
	reset,
};

enum skb_scan_ret
{
	need_next_frag = 1,
	ua_modified = 2,
};

// 根据得到的指针尝试扫描，发现结尾或发现UA或更改UA后返回对应结果。
// 输入零指针则为重置状态。
inline u_int8_t char_scan(char *data)
{
	const char str_ua_head[] = "User-Agent: ", str_ua[] = "XMURP/1.0", str_end[] = "\r\n\r\n";
	// 不算'\0'，长度分别为12、9、4
	static enum
	{
		nothing_matching,
		ua_head_matching,
		ua_modifying,
		end_matching,
	} status = nothing_matching;
	static u_int8_t covered_length;

	if(data == 0)
	{
		status = nothing_matching;
		covered_length = 0;
		return reset;
	}

	while(true)
	{
		if(status == nothing_matching)
		{
			if(*data == str_ua_head[0])
			{
				status = ua_head_matching;
				covered_length = 1;
				return next;
			}
			else if(*data == str_end[0])
			{
				status = end_matching;
				covered_length = 1;
				return next;
			}
			else
				return next;
		}
		else if(status == ua_head_matching)
		{
			if(*data == str_ua_head[covered_length])
			{
				covered_length++;
				if(covered_length == 12)
				{
					status = ua_modifying;
					covered_length = 0;
					return next;
				}
				else
					return next;
			}
			else
				status = nothing_matching;
		}
		else if(status == ua_modifying)
		{
			if(*data == '\r')
			{
				status = nothing_matching;
				return scan_finish;
			}
			else
			{
				if(covered_length < 9)
					*data = str_ua[covered_length];
				else
					*data = ' ';
				covered_length++;
				return modified_and_next;
			}
		}
		else if(status == end_matching)
		{
			if(*data == str_end[covered_length])
			{
				covered_length++;
				if(covered_length == 4)
				{
					status = nothing_matching;
					return scan_finish;
				}
				else
					return next;
			}
			else
				status = nothing_matching;
		}
	}
}

// 将数据逐字节发送给下一层，根据下一层的结果（扫描到结尾、扫描到UA、已更改UA），确定是否扫描完毕，以及是否发生了改动，返回到上一层。
inline u_int8_t skb_scan(char *data_start, char *data_end)
{
	register char *i;
	register u_int8_t ret, modified = 0;
	for(i = data_start; i < data_end; i++)
	{
		ret = char_scan(i);
		if(ret == scan_finish)
			return modified;
		else if(ret == modified_and_next)
			modified = ua_modified;
	}
	return modified + need_next_frag;
}

// 捕获数据包，检查是否符合条件。如果符合，则送到下一层，并根据下一层返回的结果，如果必要的话，重新计算校验和以及继续捕获下一个分片。
// ip地址、端口号、iph->tot_len需要网络顺序到主机顺序的转换。校验和时，除长度字段外，不需要手动进行网络顺序和主机顺序的转换。
unsigned int hook_funcion(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	register struct tcphdr *tcph;
	register struct iphdr *iph;
	register char *data_start, *data_end;

	static u_int8_t catch_next_frag = 0;
	static u_int32_t saddr, daddr, seq;
	static u_int16_t sport, dport;

	static u_int32_t n_ua_modified = 0, n_ua_modify_faild = 0;

	register u_int8_t jump_to_next_function = 0, ret;

	// 过滤发往外网的HTTP请求的包，且要求包的应用层内容不短于3字节
	if(skb == 0)
		return NF_ACCEPT;
	iph = ip_hdr(skb);
	if((ntohl(iph->daddr) & 0xffff0000) == 0xc0a80000)
		return NF_ACCEPT;
	if(iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;
	tcph = tcp_hdr(skb);
	if(ntohs(tcph->dest) != 80)
		return NF_ACCEPT;
	data_start = (char *)tcph + tcph->doff * 4;
	data_end = (char *)tcph + ntohs(iph->tot_len) - iph->ihl * 4;
	if(data_end - data_start < 4)
		return NF_ACCEPT;
	if(skb->mark & 0x100)
		return NF_ACCEPT;

	// 决定是否发送到下一层
	if(catch_next_frag && iph->saddr == saddr && iph->daddr == daddr &&
			tcph->seq == seq && tcph->source == sport && tcph->dest == dport)
		jump_to_next_function = 1;
	else if(data_end - data_start > 3)
		if(memcmp(data_start, "GET", 3) == 0 || memcmp(data_start, "POST", 4) == 0)
		{
			if(catch_next_frag)
			{
				n_ua_modify_faild++;
				char_scan(0);
				catch_next_frag = 0;
			}
			jump_to_next_function = 1;
		}
	if(!jump_to_next_function)
		return NF_ACCEPT;

	// 发送到下一层，并回收数据
	ret = skb_scan(data_start, data_end);

	// 处理返回值
	if(ret & need_next_frag)
	{
		if(!catch_next_frag)
		{
			catch_next_frag = 1;
			saddr = iph->saddr;
			daddr = iph->daddr;
			sport = tcph->source;
			dport = tcph->dest;
		}
		seq = tcph->seq + (data_end - data_start);
	}
	else
		catch_next_frag = 0;
	if(ret & ua_modified)
	{
		n_ua_modified++;
		if(n_ua_modified % 0x10000 == 0)
			printk("xmurp-ua: successfully modified %d packages, faild to modify %d packages.",
					n_ua_modified, n_ua_modify_faild);
		tcph->check = 0;
		iph->check = 0;
		skb->csum = skb_checksum(skb, iph->ihl * 4, ntohs(iph->tot_len) - iph->ihl * 4, 0);
		iph->check = ip_fast_csum(iph, iph->ihl);
		tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, ntohs(iph->tot_len) - iph->ihl * 4, IPPROTO_TCP, skb->csum);
	}

	return NF_ACCEPT;
}

static int __init hook_init(void)
{
	int ret;

	nfho.hook = hook_funcion;
	nfho.pf = NFPROTO_IPV4;
	nfho.hooknum = NF_INET_POST_ROUTING;
	nfho.priority = NF_IP_PRI_FILTER;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    ret = nf_register_net_hook(&init_net, &nfho);
#else
    ret = nf_register_hook(&nfho);
#endif
	printk("xmurp-ua start\n");
	printk("nf_register_hook returnd %d\n", ret);

	return 0;
}

//卸载模块
static void __exit hook_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_unregister_net_hook(&init_net, &nfho);
#else
    nf_unregister_hook(&nfho);
#endif
	printk("xmurp-ua stop\n");
}

module_init(hook_init);
module_exit(hook_exit);