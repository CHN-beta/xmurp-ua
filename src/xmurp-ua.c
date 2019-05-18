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

enum char_scan_ret	// 逐字节扫描函数的返回值，互斥
{
	need_next,		// 需要下一个字节来进一步判断
	ua_start,		// 接下来就是ua的内容了
	ua_scaning,		// 正在扫描ua
	ua_mobile,		// 确认为移动版ua
	ua_finish,		// ua结束（同时确认不是桌面版ua）
	httph_finish,	// http头结束（没有找到ua）
	reset,			// 状态被重置
};

struct skb_scan_ret	// 逐分片扫描函数的返回值，共存
{
	u_int8_t ua_found:1 = 0,	// 是否已经发现ua的位置
		ua_exist:1 = 0,			// 这个分片中是否存在部分或全部ua
		need_next_frag:1 = 0,		// 是否需要下一个分片
		is_mobile:1 = 0;			// 是否已经被判定为移动版ua
	char *ua_start, *ua_end;
};

// 根据得到的指针尝试扫描，发现结尾或发现UA后返回对应结果。
// 输入零指针则为重置状态。
inline u_int8_t char_scan(char *data)
{
	const char str_ua_head[] = "User-Agent: ", str_end[] = "\r\n\r\n", 
			str_wp[] = "Windows Phone", str_android = "Android", str_ipad = "iPad", str_iphone = "iPhone";
	const u_int8_t len_ua_head = 12, len_end = 4, len_wp = 13, len_android = 7, len_ipad = 4, len_iphone = 6;
	enum matching_status	// 当前字节处在匹配什么的状态
	{
		nothing,		// 无
		ua_head,		// 正在匹配ua头
		ua,				// 正在匹配ua
		end,			// 正在匹配http头尾
	}; 
	enum ua_matching_status		// 如果正在匹配ua，那么正在匹配哪个关键字
	{
		nothing,		// 无，只是在匹配ua而已
		wp,				// 正在匹配windows phone
		android,		// 正在匹配安卓
		ipad_or_iphone,	// 正在匹配ipad或iphone，因为两者都是ip开头，所以需要这样一个东西。
		ipad,			// 正在匹配ipad
		iphone,			// 正在匹配iphone
		mobile_matched,	// 已经确认为移动端
	};
	static u_int8_t status = matching_status::nothing;
	static u_int8_t ua_status = ua_matching_status::nothing;
	static u_int8_t covered_length = 0;

	if(data == 0)	// 重置状态
	{
		status = nothing;
		ua_status = ua_matching_status::nothing;
		covered_length = 0;
		return char_scan_ret::reset;
	}

	while(true)
	{
		if(status == matching_status::nothing)		// 如果没有在匹配什么，就寻找ua头或者http头尾
		{
			if(*data == str_ua_head[0])		// 发现疑似ua头
			{
				status = matching_status::ua_head;
				covered_length = 1;
				return char_scan_ret::need_next;
			}
			else if(*data == str_end[0])	// 发现疑似http头尾
			{
				status = matching_status::end;
				covered_length = 1;
				return char_scan_ret::need_next;
			}
			else							// 啥都没发现
				return char_scan_ret::need_next;
		}
		else if(status == matching_status::ua_head)			// 如果正在匹配ua头，尝试继续匹配，或将状态置为nothing后重新匹配
		{
			if(*data == str_ua_head[covered_length])		// 继续匹配ua头
			{
				covered_length++;
				if(covered_length == len_ua_head)		// ua头匹配完成
				{
					status = matching_status::ua;
					ua_status = ua_matching_status::nothing;
					covered_length = 0;
					return char_scan_ret::ua_start;
				}
				else									// 还没有匹配完
					return char_scan_ret::need_next;
			}
			else
				status = matching_status::nothing;		// 将状态置为nothing重新匹配
		}
		else if(status == matching_status::ua)			// 如果正在匹配ua，需要进一步考虑是否正在匹配ua中的特殊字段
		{
			if(ua_status == ua_matching_status::nothing)	// 如果没有在匹配特殊字段，就尝试匹配特殊字段或结尾
			{
				if(*data == '\r')				// 如果发现ua结尾
				{
					status = nothing_matching;
					ua_status = ua_matching_status::nothing;
					return char_scan_ret::ua_finish;
				}
				else if(*data == str_wp[0])		// 如果疑似匹配到windows phone
				{
					ua_status = ua_matching_status::wp;
					covered_length = 1;
					return char_scan_ret::ua_scaning;
				}
				else if(*data == str_android[0])	// 如果疑似匹配到android
				{
					ua_status = ua_matching_status::android;
					covered_length = 1;
					return char_scan_ret::ua_scaning;
				}
				else if(*data == str_ipad[0])		// 如果疑似匹配到ipad或iphone
				{
					ua_status = ua_matching_status::ipad_or_iphone;
					covered_length = 1;
					return char_scan_ret::ua_scaning;
				}
				else
					return char_scan_ret::ua_scaning;
			}
			else if(ua_status == ua_matching_status::wp)	// 如果正在匹配wp，就尝试继续匹配，或将ua状态置为nothing后重新匹配
			{
				if(*data == str_wp[covered_length])		// 如果可以继续匹配wp
				{
					covered_length++;
					if(covered_length == len_wp)		// 如果wp匹配完成
					{
						ua_status = ua_matching_status::mobile_matched;
						covered_length = 0;
						return char_scan_ret::ua_mobile;
					}
				}
				else									// 如果没有匹配上，将ua状态置为nothing后重新匹配
					ua_status = ua_matching_status::nothing;
			}
			else if(ua_status == ua_matching_status::android)	// 如果正在匹配android，就尝试继续匹配，或将ua状态置为nothing后重新匹配
			{
				if(*data == str_android[covered_length])		// 如果可以继续匹配android
				{
					covered_length++;
					if(covered_length == len_android)		// 如果匹配android完成
					{
						ua_status = ua_matching_status::mobile_matched;
						covered_length = 0;
						return char_scan_ret::ua_mobile;
					}
				}
				else									// 如果没有匹配上，将ua状态置为nothing后重新匹配
					ua_status = ua_matching_status::nothing;
			}
			else if(ua_status == ua_matching_status::ipad_or_iphone)	// 如果正在匹配ipad或iphone，就尝试继续匹配，或将ua状态置为nothing后重新匹配
			{
				if(covered_length == 1 && *data == 'P')		// 如果已经匹配‘i’、可以匹配‘P’
				{
					covered_length++;
					return char_scan_ret::ua_scaning;
				}
				else if(covered_length == 2 && *data == 'a')	// 如果已经匹配‘iP’、可以匹配‘a’
				{
					ua_status = ua_matching_status::ipad;
					covered_length++;
					return char_scan_ret::ua_scaning;
				}
				else if(covered_length == 2 && *data == 'h')	// 如果已经匹配‘iP’、可以匹配‘h’
				{
					ua_status = ua_matching_status::iphone;
					covered_length++;
					return char_scan_ret::ua_scaning;
				}
				else											// 如果没有匹配到，将ua状态置为nothing后重新匹配
				{
					ua_status = ua_matching_status::nothing;
					covered_length = 0;
				}	
			}
			else if(ua_status == ua_matching_status::ipad)	// 如果正在匹配ipad，就尝试继续匹配，或将ua状态置为nothing后重新匹配
			{
				if(*data == str_ipad[covered_length])		// 如果可以继续匹配ipad
				{
					covered_length++;
					if(covered_length == len_ipad)		// 如果匹配ipad完成
					{
						ua_status = ua_matching_status::mobile_matched;
						covered_length = 0;
						return char_scan_ret::ua_mobile;
					}
				}
				else									// 如果没有匹配上，将ua状态置为nothing后重新匹配
					ua_status = ua_matching_status::nothing;
			}
			else if(ua_status == ua_matching_status::iphone)	// 如果正在匹配iphone，就尝试继续匹配，或将ua状态置为nothing后重新匹配
			{
				if(*data == str_iphone[covered_length])		// 如果可以继续匹配iphone
				{
					covered_length++;
					if(covered_length == len_iphone)		// 如果匹配iphone完成
					{
						ua_status = ua_matching_status::mobile_matched;
						covered_length = 0;
						return char_scan_ret::ua_mobile;
					}
				}
				else									// 如果没有匹配上，将ua状态置为nothing后重新匹配
					ua_status = ua_matching_status::nothing;
			}
		}
		else if(status == matching_status::end)
		{
			if(*data == str_end[covered_length])
			{
				covered_length++;
				if(covered_length == len_end)
				{
					status = matching_status::nothing;
					covered_length = 0;
					return char_scan_ret::httph_finish;
				}
				else
					return char_scan_ret::need_next;
			}
			else
				status = matching_status::nothing;
		}
	}
}

// 将传入的区域修改掉
inline void ua_modify(char *data1_start, char *data1_end, char *data2_start, char *data2_end)
{
	const char str_ua[] = "XMURP/1.0";
	const u_int8_t len_ua = 9;
	u_int8_t i = 0;
	char *j = data1_start;
	for(; i < len_ua && j < data1_end; i++, j++)
		*j = str_ua[i];
	for(; j < data1_end; j++)
		*j = ' ';
	for(j = data2_start; i < len_ua && j < data2_end; i++, j++)
		*j = str_ua[i];
	for(; j < data2_end; j++)
		*j = ' ';
}

// 将数据逐字节发送给下一层，根据下一层的结果，确定是否改动以及改动哪里，ua_found指明在上一个分片中是否找到了ua的位置
inline u_int8_t skb_scan(char *data_start, char *data_end, u_int8_t ua_found)
{

	register char *i = data_start;
	register u_int8_t ret, is_mobile = 0;
	register struct skb_scan_ret skb_ret;
	
	// 如果在上一个分片中已经找到了ua的位置，那么这个分片的初始位置就已经是ua的一部分了，因此需要做一些预处理
	if(ua_found)
	{
		skb_ret.ua_found = 1;
		skb_ret = char_scan(i);
		if(ret == char_scan_ret:ua_scaning)
		{
			skb_ret.ua_exist = 1;
			skb_ret.ua_start = i;
		}
		else if(ret == char_scan_ret::ua_mobile)
		{
			skb_ret.ua_exist = 1;
			skb_ret.ua_start = i;
			skb_ret.ua_mobile = 1;
		}
		else if(ret == char_scan_ret::ua_finish)
		{
			skb_ret.need_next_frag = 0;
			return skb_ret;
		}
		i++;
	}

	// 扫描整个数据
	for(; i < data_end; i++)
	{
		ret = char_scan(i);
		if(ret == char_scan_ret::need_next)
			continue;
		else if(ret == char_scan_ret::ua_start)
			skb_ret.ua_found = 1;
		else if(ret == char_scan_ret:ua_scaning)
			if(!skb_ret.ua_exist)
			{
				skb_ret.ua_exist = 1;
				skb_ret.ua_start = i;
			}
			else
				continue;
		else if(ret == char_scan_ret::ua_mobile)
			skb_ret.ua_mobile = 1;
		else if(ret == char_scan_ret::ua_finish)
		{
			skb_ret.need_next_frag = 0;
			skb_ret.ua_end = i;
			return skb_ret;
		}
		else if(ret == char_scan_ret::httph_finish)
		{
			skb_ret.need_next_frag = 0;
			return skb_ret;
		}
	}

	// 如果没有扫描到需要返回的地方
	if(skb_ret.ua_exist)
		skb_ret.ua_end = data_end;
	skb_ret.need_next_frag = 1;
	return skb_ret;
}

// 捕获数据包，检查是否符合条件。如果符合，则送到下一层，并根据下一层返回的结果，如果必要的话，重新计算校验和以及继续捕获下一个分片。
// ip地址、端口号、iph->tot_len需要网络顺序到主机顺序的转换。校验和时，除长度字段外，不需要手动进行网络顺序和主机顺序的转换。
unsigned int hook_funcion(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	register struct tcphdr *tcph;
	register struct iphdr *iph;
	register char *data_start, *data_end;

	static u_int32_t saddr, daddr, seq;
	static u_int16_t sport, dport;
	static struct skb_scan_ret ret_last;
	static struct sk_buff *skb_last;

	static u_int32_t n_ua_modified = 0, n_ua_modify_faild = 0;

	register u_int8_t jump_to_next_function = 0;

	register struct skb_scan_ret ret;

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
	if(skb->mark & 1)
		return NF_ACCEPT;
	
	// 决定是否发送到下一层
	if(ret_last.need_next_frag && iph->saddr == saddr && iph->daddr == daddr &&
			tcph->seq == seq && tcph->source == sport && tcph->dest == dport)
		jump_to_next_function = 1;
	else if(data_end - data_start > 3)
		if(memcmp(data_start, "GET", 3) == 0 || memcmp(data_start, "POST", 4) == 0)
		{
			if(ret_last.need_next_frag)
			{
				n_ua_modify_faild++;
				char_scan(0);
				ret_last.need_next_frag = 0;
				ret_last.ua_found = 0;
			}
			jump_to_next_function = 1;
		}
	if(!jump_to_next_function)
		return NF_ACCEPT;

	// 发送到下一层，并回收数据
	ret = skb_scan(data_start, data_end, ret_last.ua_found);

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