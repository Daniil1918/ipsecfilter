#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>


static unsigned int ipv4_ipsec_filter_hook(void *priv,
                                          struct sk_buff *skb,
                                          const struct nf_hook_state *state)
{
    struct iphdr *ip4_hdr;

    ip4_hdr = ip_hdr(skb);
    if ((ip4_hdr->protocol == IPPROTO_ESP) ||
        (ip4_hdr->protocol == IPPROTO_AH))
        return NF_DROP;

    return NF_ACCEPT;
}

static unsigned int ipv6_ipsec_filter_hook(void *priv,
                                          struct sk_buff *skb,
                                          const struct nf_hook_state *state)
{
    struct ipv6hdr *ip6_hdr;

    ip6_hdr = ipv6_hdr(skb);
    if ((ip6_hdr->nexthdr == IPPROTO_ESP) ||
        (ip6_hdr->nexthdr == IPPROTO_AH))
        return NF_DROP;

    return NF_ACCEPT;
}

static const struct nf_hook_ops ipsec_filter_ops[] = {
    {
        .hook     = ipv4_ipsec_filter_hook,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FILTER,
    },
    {
        .hook     = ipv4_ipsec_filter_hook,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FILTER,
    },
#if IS_ENABLED(CONFIG_IPV6)
    {
        .hook     = ipv6_ipsec_filter_hook,
        .pf       = NFPROTO_IPV6,
        .hooknum  = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FILTER,
    },
    {
        .hook     = ipv6_ipsec_filter_hook,
        .pf       = NFPROTO_IPV6,
        .hooknum  = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FILTER,
    },
#endif
};

static int __net_init filter_net_init(struct net *net)
{
    return nf_register_net_hooks(net, ipsec_filter_ops,
                                ARRAY_SIZE(ipsec_filter_ops));
}

static void __net_exit filter_net_exit(struct net *net)
{
    nf_unregister_net_hooks(net, ipsec_filter_ops,
                           ARRAY_SIZE(ipsec_filter_ops));
}

static struct pernet_operations filter_net_ops = {
    .init = filter_net_init,
    .exit = filter_net_exit,
};

static int __init filter_init(void)
{
    printk(KERN_INFO "IPsec packet filter init!\n");

    return register_pernet_subsys(&filter_net_ops);
}

static void __exit filter_exit(void)
{
    printk(KERN_INFO "IPsec packet filter exit.\n");

    unregister_pernet_subsys(&filter_net_ops);
}

module_init(filter_init);
module_exit(filter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Leonov Daniil");
MODULE_DESCRIPTION("Packet filter for IPsec.");
