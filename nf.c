#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>

#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/inet.h>

MODULE_LICENSE("GPL");

static char * ifname = "eth2";

unsigned int my_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *)) 
{
    struct iphdr *iph = ip_hdr(skb);
    if (iph->protocol == 6 && !strcmp(out->name, ifname))
    {
        struct tcphdr *tcph, _tcph;
        tcph = skb_header_pointer(skb, iph->ihl << 2, sizeof(_tcph), &_tcph);

        printk(KERN_INFO "%s %d.%d.%d.%d %d.%d.%d.%d %d %d %d %d\n", 
                out->name,
                ((unsigned char*)&(iph->saddr))[0],
                ((unsigned char*)&(iph->saddr))[1],
                ((unsigned char*)&(iph->saddr))[2],
                ((unsigned char*)&(iph->saddr))[3],
                ((unsigned char*)&(iph->daddr))[0],
                ((unsigned char*)&(iph->daddr))[1],
                ((unsigned char*)&(iph->daddr))[2],
                ((unsigned char*)&(iph->daddr))[3],
                ntohs(tcph->source),
                ntohs(tcph->dest),
                tcph->ack,
                (unsigned int)ntohl(tcph->ack_seq)
              );
    }
    return NF_ACCEPT;
}


static struct nf_hook_ops hook_ops = {
    .hook = my_hook,
    .owner = THIS_MODULE,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_OUT,
    /*.hooknum = NF_IP_LOCAL_OUT,*/
    .priority = NF_IP_PRI_FIRST

};

int init_module(void)
{

    nf_register_hook(&hook_ops);
    printk(KERN_INFO "init\n");
    return 0;
}

void cleanup_module(void)
{
    nf_unregister_hook(&hook_ops);
    printk(KERN_INFO "done\n");
}
