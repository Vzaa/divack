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

#if 0
#define debug(M...) printk(M)
#else
#define debug(M...)
#endif

#define DIV_THRESHOLD 20
#define DIFF_THRESHOLD 1000
#define HASHSIZE 65536

static char * ifname = "eth0";

typedef struct{
    int used;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 last_seq;
    int first_ack;
    int div_cnt;
    spinlock_t lock;
} tcp_conn_t;

static tcp_conn_t tracked[HASHSIZE];

static u16 xor_hash(u32 daddr, u16 sport, u16 dport)
{
    int i;
    u16 hash = 0xdeadbeef;
    for (i = 0; i < sizeof(daddr) / sizeof(hash); ++i) {
        hash ^= ((u16*) (&daddr))[i];
    }
    hash ^= sport;
    hash ^= dport;
    return hash;
}


static void update_ack_seq(struct sk_buff * skb, u32 new_seq_no)
{
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph, _tcph;
    tcph = skb_header_pointer(skb, iph->ihl << 2, sizeof(_tcph), &_tcph);
    tcph->ack_seq = htonl(new_seq_no);
}

unsigned int my_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = ip_hdr(skb);
    tcp_conn_t * conn = NULL;
    if (iph->protocol == 6 && !strcmp(out->name, ifname)) {
        u16 hash;
        struct tcphdr *tcph, _tcph;
        tcph = skb_header_pointer(skb, iph->ihl << 2, sizeof(_tcph), &_tcph);

        hash = xor_hash(iph->daddr, tcph->source, tcph->dest);
        conn = &tracked[hash];

        if (tcph->syn) {
            spin_lock(&conn->lock);
            if (conn->used == 0 ||
                    (ntohl(iph->daddr) == conn->daddr &&
                     ntohs(tcph->source) == conn->sport &&
                     ntohs(tcph->dest) == conn->dport)) {
                printk(KERN_INFO "Track %u.%u.%u.%u %u %u\n",
                        ((unsigned char*)&(iph->daddr))[0],
                        ((unsigned char*)&(iph->daddr))[1],
                        ((unsigned char*)&(iph->daddr))[2],
                        ((unsigned char*)&(iph->daddr))[3],
                        ntohs(tcph->source),
                        ntohs(tcph->dest)
                     );
                debug(KERN_INFO "hash: %u\n", hash);
                conn->used = 1;
                conn->first_ack = 0;
                conn->div_cnt = 0;
                conn->daddr = ntohl(iph->daddr);
                conn->sport = ntohs(tcph->source);
                conn->dport = ntohs(tcph->dest);
            }
            else {
                printk(KERN_INFO "HASH OVERLAP!!! %s %u.%u.%u.%u %u %u overlap with existing %u.%u.%u.%u %u %u\n",
                        out->name,
                        ((unsigned char*)&(iph->daddr))[0],
                        ((unsigned char*)&(iph->daddr))[1],
                        ((unsigned char*)&(iph->daddr))[2],
                        ((unsigned char*)&(iph->daddr))[3],
                        ntohs(tcph->source),
                        ntohs(tcph->dest),
                        ((unsigned char*)&(conn->daddr))[0],
                        ((unsigned char*)&(conn->daddr))[1],
                        ((unsigned char*)&(conn->daddr))[2],
                        ((unsigned char*)&(conn->daddr))[3],
                        conn->sport,
                        conn->dport
                      );
            }
            spin_unlock(&conn->lock);
        }
        else if (tcph->fin || tcph->rst) {
            spin_lock(&conn->lock);
            if (conn->used &&
                    ntohl(iph->daddr) == conn->daddr &&
                    ntohs(tcph->source) == conn->sport &&
                    ntohs(tcph->dest) == conn->dport) {
                conn->used = 0;
                printk(KERN_INFO "CLOSE %s %u.%u.%u.%u %u %u\n",
                        out->name,
                        ((unsigned char*)&(iph->daddr))[0],
                        ((unsigned char*)&(iph->daddr))[1],
                        ((unsigned char*)&(iph->daddr))[2],
                        ((unsigned char*)&(iph->daddr))[3],
                        ntohs(tcph->source),
                        ntohs(tcph->dest)
                     );
            }
            spin_unlock(&conn->lock);
        }
        else if (tcph->ack) {
            spin_lock(&conn->lock);
            if (conn->used &&
                    ntohl(iph->daddr) == conn->daddr &&
                    ntohs(tcph->source) == conn->sport &&
                    ntohs(tcph->dest) == conn->dport) {
                u32 new_seq = ntohl(tcph->ack_seq);
                if (!conn->first_ack) {
                    conn->last_seq = new_seq;
                    conn->first_ack = 1;
                }
                else {
                    struct sk_buff * skb_new;
                    u32 diff = new_seq - conn->last_seq;
                    debug("%u bytes since last ack\n", diff);
                    conn->last_seq = new_seq;
                    if (diff > DIFF_THRESHOLD && conn->div_cnt < DIV_THRESHOLD) {
                        int div_size = diff / 3;
                        skb_new = skb_copy(skb, GFP_ATOMIC);
                        if (skb_new != NULL) {
                            debug("div w seq no %u\n", conn->last_seq - (2 * div_size));
                            update_ack_seq(skb_new, conn->last_seq - (2 * div_size));
                            okfn(skb_new);
                        }

                        skb_new = skb_copy(skb, GFP_ATOMIC);
                        if (skb_new != NULL) {
                            debug("div w seq no %u\n", conn->last_seq - div_size);
                            update_ack_seq(skb_new, conn->last_seq - div_size);
                            okfn(skb_new);
                        }
                        conn->div_cnt += 2;
                        if (conn->div_cnt >= DIV_THRESHOLD) {
                            conn->used = 0;
                            printk(KERN_INFO "divack limit reached %s %u.%u.%u.%u %u %u\n",
                                    out->name,
                                    ((unsigned char*)&(iph->daddr))[0],
                                    ((unsigned char*)&(iph->daddr))[1],
                                    ((unsigned char*)&(iph->daddr))[2],
                                    ((unsigned char*)&(iph->daddr))[3],
                                    ntohs(tcph->source),
                                    ntohs(tcph->dest)
                                 );
                        }
                    }
                }
            }
            spin_unlock(&conn->lock);
        }
    }
    return NF_ACCEPT;
}


static struct nf_hook_ops hook_ops = {
    .hook = my_hook,
    .owner = THIS_MODULE,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST
};

int init_module(void)
{
    int i;
    for (i = 0; i < HASHSIZE; ++i) {
        spin_lock_init(&tracked[i].lock);
        tracked[i].used = 0;
        tracked[i].daddr = 0;
        tracked[i].sport = 0;
        tracked[i].dport = 0;
        tracked[i].last_seq = 0;
    }
    nf_register_hook(&hook_ops);
    printk(KERN_INFO "divack: init\n");
    return 0;
}

void cleanup_module(void)
{
    nf_unregister_hook(&hook_ops);
    printk(KERN_INFO "divack: remove\n");
}

MODULE_LICENSE("GPL");
