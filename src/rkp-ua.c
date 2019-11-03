#include "rkpManager.h"

static struct nf_hook_ops nfho;
static struct rkpManager* rkpm;
static time_t last_flush;

unsigned int hook_funcion(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	unsigned rtn;
	static bool crashed = 0;

	static unsigned n_skb_captured = 0, n_skb_captured_lastPrint = 1;

	if(crashed)
		return NF_ACCEPT;
	if(!rkpSettings_capture(skb))
		return NF_ACCEPT;

	rtn = rkpManager_execute(rkpm, skb);

	n_skb_captured++;
	if(n_skb_captured == n_skb_captured_lastPrint * 2)
	{
		printk("rkp-ua: Captured %d packages.\n", n_skb_captured);
		n_skb_captured_lastPrint *= 2;
	}

	if(rtn == NF_DROP_ERR(1))
	{
		printk("rkp-ua: Crashed.\n");
		crashed = 1;
		rkpManager_del(rkpm);
		return NF_STOLEN;
	}
	else 
		return rtn;
}

static int __init hook_init(void)
{
	int ret;

	rkpm = rkpManager_new();
	last_flush = now();

	memcpy(str_ua_rkp, "RKP/", 4);
	memcpy(str_ua_rkp, VERSION, 3);

	nfho.hook = hook_funcion;
	nfho.pf = NFPROTO_IPV4;
	nfho.hooknum = NF_INET_POST_ROUTING;
	nfho.priority = NF_IP_PRI_NAT_SRC;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    ret = nf_register_net_hook(&init_net, &nfho);
#else
    ret = nf_register_hook(&nfho);
#endif

	printk("rkp-ua: Started, version %s\n", VERSION);
	printk("rkp-ua: nf_register_hook returnd %d.\n", ret);
	printk("rkp-ua: mode_advanced=%c, mark_capture=0x%x, mark_request=0x%x, mark_first=0x%x, mark_preserve=0x%x.\n",
			'n' + mode_advanced * ('y' - 'n'), mark_capture, mark_request, mark_first, mark_preserve);
	printk("rkp-ua: str_preserve:\n");
	for(ret = 0; ret < n_str_preserve; ret++)
		printk("\t%s\n", str_preserve[ret]);

	return 0;
}

static void __exit hook_exit(void)
{
	rkpManager_del(rkpm);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_unregister_net_hook(&init_net, &nfho);
#else
    nf_unregister_hook(&nfho);
#endif
	printk("rkp-ua: Stopped.\n");
}

module_init(hook_init);
module_exit(hook_exit);

MODULE_AUTHOR("Haonan Chen");
MODULE_DESCRIPTION("Modify UA in HTTP for anti-detection about amount of devices behind NAT.");
MODULE_LICENSE("GPL");