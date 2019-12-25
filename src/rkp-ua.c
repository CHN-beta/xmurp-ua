#include "rkpManager.h"

static struct nf_hook_ops nfho;
static struct rkpManager* rkpm;

unsigned int hook_funcion(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	unsigned rtn;
	static bool crashed = false;

	static unsigned n_skb_captured = 0, n_skb_captured_lastPrint = 1;

	if(crashed)
		return NF_ACCEPT;
	if(!rkpSettings_capture(skb))
		return NF_ACCEPT;
#ifdef RKP_DEBUG
	printk("hook_function captured a packet.\n");
#endif
	rtn = rkpManager_execute(rkpm, skb);

	n_skb_captured++;
	if(n_skb_captured == n_skb_captured_lastPrint * 2)
	{
		printk("rkp-ua: Captured %d packages.\n", n_skb_captured);
		n_skb_captured_lastPrint *= 2;
	}
#ifdef RKP_DEBUG
	printk("hook_function end.\n");
#endif
	return rtn;
}

static int __init hook_init(void)
{
	int ret;

	rkpm = rkpManager_new();

	memcpy(str_ua_rkp, "RKP/", 4);
	memcpy(str_ua_rkp + 4, VERSION, 2);
	memcpy(str_ua_rkp + 6, ".0", 3);

	nfho.hook = hook_funcion;
	nfho.pf = NFPROTO_IPV4;
	nfho.hooknum = NF_INET_POST_ROUTING;
	nfho.priority = NF_IP_PRI_RAW;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    ret = nf_register_net_hook(&init_net, &nfho);
#else
    ret = nf_register_hook(&nfho);
#endif

	printk("rkp-ua: Started, version %s\n", VERSION);
	printk("rkp-ua: nf_register_hook returnd %d.\n", ret);
	printk("rkp-ua: autocapture=%c, mark_capture=0x%x, mark_first=0x%x.\n",
			'n' + autocapture * ('y' - 'n'), mark_capture, mark_first);
	printk("rkp-ua: str_preserve: %d\n", n_str_preserve);
	for(ret = 0; ret < n_str_preserve; ret++)
		printk("\t%s\n", str_preserve[ret]);
#ifdef RKP_DEBUG
	printk("str_ua_rkp: %s\n", str_ua_rkp);
#endif

	return 0;
}

static void __exit hook_exit(void)
{
	if(rkpm != 0)
		rkpManager_delete(rkpm);

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