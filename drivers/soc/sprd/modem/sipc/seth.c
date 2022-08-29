/*
 * Copyright (C) 2018 Spreadtrum Communications Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define pr_fmt(fmt) "SETH: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_arp.h>
#include <asm/byteorder.h>
#include <linux/platform_device.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/of_device.h>
#include <linux/sipc.h>
#if defined(CONFIG_SPRD_SFP_SUPPORT) && !defined(CONFIG_SPRD_IPA_SUPPORT)
#include <net/sfp.h>
#endif

/* Defination of sblock length, set to 1600 for non-zerocopy solution, */
/* otherwise, modem(wcdma) will assert */

#define SETH_BLOCK_SIZE	1600

/* Device status */
#define DEV_ON 1
#define DEV_OFF 0

/* Tx pkt return value */
#define SETH_TX_SUCCESS		 0
#define SETH_TX_NO_BLK		-1
#define SETH_TX_FAILED		-2

#define SETH_NAPI_WEIGHT 64
#define SETH_TX_WEIGHT 16

#ifndef ARPHRD_RAWIP
#define ARPHRD_RAWIP 530
#endif

#define SETH_NAME_SIZE 16

/* Struct of data transfer statistics */
struct seth_dtrans_stats {
	u32 rx_pkt_max;
	u32 rx_pkt_min;
	u32 rx_sum;
	u32 rx_cnt;
	u32 rx_alloc_fails;

	u32 tx_pkt_max;
	u32 tx_pkt_min;
	u32 tx_sum;
	u32 tx_cnt;
	u32 tx_ping_cnt;
	u32 tx_ack_cnt;
};

struct seth_init_data {
	char *name;
	u8 dst;
	u8 channel;
	u32 blocknum;
	u32 poolsize;
};

/*
 * struct seth: device instance data for seth
 * @stats: net statistics
 * @netdev: linux net device
 * @pdata: platform data
 * @state: device state
 * @txstate: device txstate
 * @is_rawip : whether is rawip solution
 * @rx_busy: whether seth rx is busy
 * @rx_timer: timer for seth rx
 * @txpending: seth tx resend count
 * @tx_timer: timer for seth tx
 * @napi: napi instance
 * @dt_stats: record data_transfer statistics
 */
struct seth {
	struct net_device_stats stats;
	struct net_device *netdev;
	struct seth_init_data *pdata;
	int state;
	int txstate;
	int is_rawip;

	atomic_t rx_busy;
	struct timer_list rx_timer;

	atomic_t txpending;
	struct timer_list tx_timer;
	struct napi_struct napi;
	struct seth_dtrans_stats dt_stats;
};

/* we decide disable GRO, since it alawys conflit with others */
static u32 gro_enable;

static struct dentry *root;
static int seth_debugfs_mknod(void *root, void *data);
static void seth_rx_timer_handler(unsigned long data);

static inline void seth_dt_stats_init(struct seth_dtrans_stats *stats)
{
	memset(stats, 0, sizeof(struct seth_dtrans_stats));
	stats->rx_pkt_min = 0xff;
	stats->tx_pkt_min = 0xff;
}

static inline void seth_rx_stats_update(
			struct seth_dtrans_stats *stats, u32 cnt)
{
	stats->rx_pkt_max = max(stats->rx_pkt_max, cnt);
	stats->rx_pkt_min = min(stats->rx_pkt_min, cnt);
	stats->rx_sum += cnt;
	stats->rx_cnt++;
}

static inline void seth_tx_stats_update(
			struct seth_dtrans_stats *stats, u32 cnt)
{
	stats->tx_pkt_max = max(stats->tx_pkt_max, cnt);
	stats->tx_pkt_min = min(stats->tx_pkt_min, cnt);
	stats->tx_sum += cnt;
	stats->tx_cnt++;
}

static inline void pkt_info_print(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	if (iph->version == 4)
		dev_dbg(
			NULL,
			"%pI4->%pI4, id=%d, len=%d\n",
			&iph->saddr, &iph->daddr,
			ntohs(iph->id), ntohs(iph->tot_len));
}

static void
seth_rx_prepare_skb(struct seth *seth, struct sk_buff *skb, struct sblock *blk)
{
	struct ethhdr *peth;
	struct iphdr *iph;

	if (seth->is_rawip) {
		skb_reserve(skb, NET_IP_ALIGN);
		skb_reset_mac_header(skb);
		peth = (struct ethhdr *)skb->data;
		skb_reserve(skb, ETH_HLEN);
		skb_reset_network_header(skb);
		unalign_memcpy(skb->data, blk->addr, blk->length);
		skb->dev = seth->netdev;
		iph = ip_hdr(skb);
		if (iph->version == 4)
			skb->protocol = htons(ETH_P_IP);
		else
			skb->protocol = htons(ETH_P_IPV6);
		/*
		 * Add an identical fake ethernet hdr
		 * to avoid out-of-order by GRO
		 */
		ether_addr_copy(peth->h_source, "000000");
		ether_addr_copy(peth->h_dest, "000001");
		peth->h_proto = skb->protocol;
		skb_put(skb, blk->length);
	} else {
		skb_reserve(skb, NET_IP_ALIGN);
		unalign_memcpy(skb->data, blk->addr, blk->length);
		skb_put(skb, blk->length);
		skb->protocol = eth_type_trans(skb, seth->netdev);
		skb_reset_network_header(skb);
	}
	skb->pkt_type = PACKET_HOST;
	skb->ip_summed = CHECKSUM_NONE;
}

#if defined(CONFIG_SPRD_SFP_SUPPORT) && !defined(CONFIG_SPRD_IPA_SUPPORT)
static int seth_sfp_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	const struct net_device_ops *ops = dev->netdev_ops;

	return ops->ndo_start_xmit(skb, dev);
}
#endif

static int seth_rx_poll_handler(struct napi_struct *napi, int budget)
{
	struct seth *seth = container_of(napi, struct seth, napi);
	struct sk_buff *skb;
	struct seth_init_data *pdata;
	struct sblock blk = {};
	struct seth_dtrans_stats *dt_stats;
	int skb_cnt, blk_ret, ret;
#if defined(CONFIG_SPRD_SFP_SUPPORT) && !defined(CONFIG_SPRD_IPA_SUPPORT)
	struct net_device *net;
	int out_index;
#endif

	if (!seth) {
		dev_err(NULL, "%s no seth device\n", __func__);
		return 0;
	}

	pdata = seth->pdata;
	dt_stats = &seth->dt_stats;
	blk_ret = 0;
	skb_cnt = 0;
	/* Keep polling, until the sblock rx ring is empty */
	while ((budget - skb_cnt) && !blk_ret) {
		blk_ret = SBLOCK_RECEIVE(pdata->dst, pdata->channel, &blk, 0);
		if (blk_ret) {
			dev_dbg(
				&seth->netdev->dev,
				"receive sblock error %d\n",
				blk_ret);
			continue;
		}
		if (seth->is_rawip)
			skb = dev_alloc_skb(blk.length
					+ ETH_HLEN + NET_IP_ALIGN);
		else
			skb = dev_alloc_skb(blk.length + NET_IP_ALIGN);
		if (!skb) {
			seth->stats.rx_dropped++;
			dev_err(&seth->netdev->dev, "failed to alloc skb!\n");
			ret = SBLOCK_RELEASE(pdata->dst, pdata->channel, &blk);
			if (ret)
				dev_err(
					&seth->netdev->dev,
					"release sblock failed %d\n",
					ret);
			dt_stats->rx_alloc_fails++;
			continue;
		}
		/* Prepare skb for IP layer */
		seth_rx_prepare_skb(seth, skb, &blk);
		/* Print debug info: ipid for v4*/
		pkt_info_print(skb);
		/* Release sblock */
		ret = SBLOCK_RELEASE(pdata->dst, pdata->channel, &blk);
		if (ret)
			dev_err(
				&seth->netdev->dev,
				"release sblock error %d\n",
				ret);
		/* Update fifo rd_ptr */
		seth->stats.rx_bytes += skb->len;
		seth->stats.rx_packets++;
#if defined(CONFIG_SPRD_SFP_SUPPORT) && !defined(CONFIG_SPRD_IPA_SUPPORT)
		ret = soft_fastpath_process(SFP_INTERFACE_LTE,
					(void *)skb, NULL, NULL, &out_index);
		if (!ret) {
			net = netdev_get_by_index(out_index);
			skb_cnt++;
			if (!net || seth_sfp_start_xmit(skb, net)) {
				dev_kfree_skb_any(skb);
				pr_err("fast xmit fail, netif recv!\n");
			}
			continue;
		}
#endif
		/* Send to IP layer */
		if (gro_enable)
			napi_gro_receive(napi, skb);
		else
			netif_receive_skb(skb);
		/* Update skb counter */
		skb_cnt++;
	}

	/* Update rx statistics */
	seth_rx_stats_update(dt_stats, skb_cnt);

	if (skb_cnt >= 0 && budget > skb_cnt) {
		napi_complete(napi);
		atomic_dec(&seth->rx_busy);

		/* To guarantee that any arrived sblock(s) can
		 * be processed even if there are no events issued by CP
		 */
		if (SBLOCK_GET_ARRIVED_COUNT(pdata->dst, pdata->channel) > 0) {
			/* Start a timer with 2 jiffies expries (20 ms) */
			seth->rx_timer.function = seth_rx_timer_handler;
			seth->rx_timer.expires = jiffies + HZ / 50;
			seth->rx_timer.data = (unsigned long)seth;
			mod_timer(&seth->rx_timer, seth->rx_timer.expires);
			dev_dbg(
				&seth->netdev->dev,
				"start rx_timer, jiffies %lu.\n",
				jiffies);
		}
	}
	return skb_cnt;
}

/* Tx_ready handler. */
static void seth_tx_ready_handler(void *data)
{
	struct seth *seth = (struct seth *)data;

	if (seth->state != DEV_ON) {
		seth->state = DEV_ON;
		seth->txstate = DEV_ON;
		if (!netif_carrier_ok(seth->netdev))
			netif_carrier_on(seth->netdev);
	} else {
		seth->state = DEV_OFF;
		seth->txstate = DEV_OFF;
		if (netif_carrier_ok(seth->netdev))
			netif_carrier_off(seth->netdev);
	}
}

/* Tx_open handler. */
static void seth_tx_open_handler(void *data)
{
	struct seth *seth = (struct seth *)data;

	seth->txstate = DEV_ON;
}

/* Tx_close handler. */
static void seth_tx_close_handler(void *data)
{
	struct seth *seth = (struct seth *)data;

	if (seth->state == DEV_OFF)
		return;
	seth->state = DEV_OFF;
	seth->txstate = DEV_OFF;
	if (netif_carrier_ok(seth->netdev))
		netif_carrier_off(seth->netdev);
}

static void seth_rx_handler(void *data)
{
	struct seth *seth = (struct seth *)data;

	if (!seth)
		return;

	if (seth->state != DEV_ON) {
		dev_err(&seth->netdev->dev, "dev is OFF, state=%d\n",
			seth->state);
		return;
	}

	/* If the poll handler has been done, trigger to schedule*/
	if (!atomic_cmpxchg(&seth->rx_busy, 0, 1)) {
		/* Update rx stats*/
		napi_schedule(&seth->napi);
		/* Trigger a NET_RX_SOFTIRQ softirq directly */
		raise_softirq(NET_RX_SOFTIRQ);
	}
}

static void seth_rx_timer_handler(unsigned long data)
{
	seth_rx_handler((void *)data);
}

/* Tx_close handler. */
static void seth_tx_pre_handler(void *data)
{
	struct seth *seth = (struct seth *)data;

	if (seth->txstate == DEV_ON)
		return;
	seth->txstate = DEV_ON;
	if (netif_queue_stopped(seth->netdev))
		netif_wake_queue(seth->netdev);
}

static void seth_handler(int event, void *data)
{
	struct seth *seth = (struct seth *)data;

	WARN_ON(!seth);

	switch (event) {
	case SBLOCK_NOTIFY_GET:
		seth_tx_pre_handler(seth);
		break;
	case SBLOCK_NOTIFY_RECV:
		del_timer(&seth->rx_timer);
		seth_rx_handler(seth);
		break;
	case SBLOCK_NOTIFY_STATUS:
		seth_tx_ready_handler(seth);
		break;
	case SBLOCK_NOTIFY_OPEN:
		seth_tx_open_handler(seth);
		break;
	case SBLOCK_NOTIFY_CLOSE:
		seth_tx_close_handler(seth);
		break;
	default:
		dev_err(
			&seth->netdev->dev,
			"Received event is invalid(event=%d)\n", event);
	}
}

static int seth_tx_pkt(void *data, struct sk_buff *skb, int is_ack)
{
	struct sblock blk = {};
	struct seth *seth = netdev_priv(data);
	struct seth_init_data *pdata = seth->pdata;
	int ret;

	/* Get a free sblock. */
	ret = SBLOCK_GET(pdata->dst, pdata->channel, &blk, is_ack, 0);
	if (ret) {
		dev_err(
			&seth->netdev->dev,
			"Get free sblock failed(%d), drop data!\n", ret);
		seth->stats.tx_fifo_errors++;
		return SETH_TX_NO_BLK;
	}

	if (blk.length < skb->len) {
		dev_err(
			&seth->netdev->dev,
			"Sblock %d too small, skb %d\n",
			blk.length,
			skb->len);
		goto send_fail;
	}
	if (seth->is_rawip)
		skb_pull_inline(skb, ETH_HLEN);
	blk.length = skb->len;
	unalign_memcpy(blk.addr, skb->data, skb->len);
	/* Copy the content into smem and trigger a smsg to the peer side */
	if (seth->is_rawip)
		ret = SBLOCK_SEND_PREPARE(pdata->dst, pdata->channel, &blk);
	else
		ret = SBLOCK_SEND(pdata->dst, pdata->channel, &blk);
	if (ret < 0) {
		dev_err(
			&seth->netdev->dev,
			"Sblock_send fail, error %d\n", ret);
		goto send_fail;
	}
	/* Update the statistics */
	seth->stats.tx_bytes += skb->len;
	seth->stats.tx_packets++;

	dev_kfree_skb_any(skb);

	atomic_inc(&seth->txpending);
	return SETH_TX_SUCCESS;
send_fail:
	/* Recycle the unused sblock */
	SBLOCK_PUT(pdata->dst, pdata->channel, &blk);
	seth->stats.tx_fifo_errors++;
	netif_wake_queue(seth->netdev);
	return SETH_TX_FAILED;
}

static void seth_tx_flush(unsigned long data)
{
	int ret;
	u32 cnt;
	struct seth *seth = netdev_priv((void *)data);
	struct seth_init_data *pdata = seth->pdata;

	cnt = (u32)atomic_read(&seth->txpending);
	ret = SBLOCK_SEND_FINISH(pdata->dst, pdata->channel);
	seth_tx_stats_update(&seth->dt_stats, cnt);
	if (ret)
		dev_err(&seth->netdev->dev, "seth tx failed(%d)!\n", ret);
	else
		atomic_set(&seth->txpending, 0);
}

static int get_pkt_proto(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct ipv6hdr *ipv6_hdr;

	if (iph->version == 4)
		return iph->protocol;

	ipv6_hdr = (struct ipv6hdr *)iph;
	return ipv6_hdr->nexthdr;
}

static struct tcphdr *get_pkt_tcphdr(struct sk_buff *skb)
{
	u8 iph_len;
	struct iphdr *iph = ip_hdr(skb);

	if (iph->version == 4)
		iph_len = iph->ihl * 4;
	else
		iph_len = sizeof(struct ipv6hdr);
	return (struct tcphdr *)((char *)iph + iph_len);
}

/*
 * The orginal idea of pkt_is_ack() is to delay a pkt with data len > 0
 * for pkt aggregation purpose.
 * however, except syn/rst/fin, the ack flag is always 1.
 * So actually this function does not work at all.
 * Since it remains untested, and we do not want to take the risk,
 * we just keep it simple as below, that is we do not delay all tcp pkts.
 */
static bool pkt_need_nodelay(struct sk_buff *skb)
{
	u8 protocol = get_pkt_proto(skb);

	if (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6 ||
	    protocol == IPPROTO_TCP)
		return true;
	return false;
}

static bool pkt_use_ackpool(struct sk_buff *skb)
{
	struct tcphdr *tcph;
	struct ipv6hdr *ip6h;
	struct iphdr *iph = ip_hdr(skb);
	u8 protocol = get_pkt_proto(skb);

	if (skb->len > SIPX_ACK_BLK_LEN)
		return false;

	/* TODO what if ipv6(TCP) nexthdr is not TCP */
	if (protocol == IPPROTO_TCP) {
		tcph = get_pkt_tcphdr(skb);
		/* we simply consider a tcp ack
		 * is a tcp pkt with data_len = 0
		 */
		if (iph->version == 4) {
			if ((ntohs(iph->tot_len) - iph->ihl * 4)
				== tcph->doff * 4)
				return true;
		} else if (iph->version == 6) {
			ip6h = (struct ipv6hdr *)iph;
			if (ntohs(ip6h->payload_len) == tcph->doff * 4)
				return true;
		}
	}
	return false;
}

/* Transmit interface */
static int seth_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct seth *seth = netdev_priv(dev);
	struct seth_dtrans_stats *dt_stats;
	int ret, blk_cnt;
	bool nodelay, ack_pool;

	if (seth->state != DEV_ON) {
		dev_err(&dev->dev, "xmit the state is off\n");
		netif_carrier_off(dev);
		seth->stats.tx_carrier_errors++;
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	/* Update tx statistics */
	dt_stats = &seth->dt_stats;
	nodelay = pkt_need_nodelay(skb);
	ack_pool = pkt_use_ackpool(skb);

	ret = seth_tx_pkt(dev, skb, ack_pool);
	if (ret == SETH_TX_NO_BLK) {
		/* if there are no available sblks, enter flow control */
		seth->txstate = DEV_OFF;
		netif_stop_queue(dev);
		/* anyway, flush the stored sblks */
		seth_tx_flush((unsigned long)dev);
		return NETDEV_TX_BUSY;
	} else if (ret == SETH_TX_FAILED) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
	/*
	 * If there are no available sblock for
	 * subsequent skb, start flow control
	 */
	blk_cnt = SBLOCK_GET_FREE_COUNT(seth->pdata->dst, seth->pdata->channel);
	if (!blk_cnt) {
		dev_dbg(&dev->dev, "start flow control\n");
		seth->txstate = DEV_OFF;
		netif_stop_queue(dev);
	}

	if ((atomic_read(&seth->txpending) >= SETH_TX_WEIGHT) || nodelay) {
		del_timer(&seth->tx_timer);
		seth_tx_flush((unsigned long)dev);
		dev_dbg(&dev->dev, "%s:at once\n", __func__);
	} else if (atomic_read(&seth->txpending) == 1) {
		/* start a timer with 1 jiffy expries (10 ms) */
		seth->tx_timer.function = seth_tx_flush;
		seth->tx_timer.expires = jiffies + HZ / 100;
		seth->tx_timer.data = (unsigned long)dev;
		mod_timer(&seth->tx_timer, seth->tx_timer.expires);
		dev_dbg(&dev->dev, "%s:Timer\n", __func__);
	}
	return NETDEV_TX_OK;
}

/* Open interface */
static int seth_open(struct net_device *dev)
{
	struct seth *seth = netdev_priv(dev);
	struct seth_init_data *pdata;
	struct sblock blk = {};
	int ret = 0, num = 0;

	dev_info(&dev->dev, "open %s!\n", dev->name);

	if (!seth)
		return -ENODEV;

	pdata = seth->pdata;

	/* clean the resident sblocks */
	while (!ret && num < pdata->blocknum) {
		ret = SBLOCK_RECEIVE(pdata->dst, pdata->channel, &blk, 0);
		if (!ret) {
			SBLOCK_RELEASE(pdata->dst, pdata->channel, &blk);
			num++;
		}
	}
	dev_info(&dev->dev, "%s clean %d resident sblocks\n", __func__, num);

	/* Reset stats */
	memset(&seth->stats, 0, sizeof(seth->stats));

	if (!netif_carrier_ok(seth->netdev)) {
		dev_dbg(&dev->dev, "%s netif_carrier_on\n", __func__);
		netif_carrier_on(seth->netdev);
	}

	atomic_set(&seth->rx_busy, 0);
	napi_enable(&seth->napi);
	seth_dt_stats_init(&seth->dt_stats);
	seth->txstate = DEV_ON;
	seth->state = DEV_ON;
	netif_start_queue(dev);

	return 0;
}

/* Close interface */
static int seth_close(struct net_device *dev)
{
	struct seth *seth = netdev_priv(dev);

	dev_info(&dev->dev, "close %s!\n", dev->name);

	seth->txstate = DEV_OFF;
	seth->state = DEV_OFF;
	napi_disable(&seth->napi);
	netif_stop_queue(dev);

	return 0;
}

static struct net_device_stats *seth_get_stats(struct net_device *dev)
{
	struct seth *seth = netdev_priv(dev);

	return &seth->stats;
}

static void seth_tx_timeout(struct net_device *dev)
{
	struct seth *seth = netdev_priv(dev);

	dev_dbg(&dev->dev, "%s\n", __func__);
	if (seth->txstate != DEV_ON) {
		seth->txstate = DEV_ON;
		netif_wake_queue(dev);
	}
}

static const struct net_device_ops seth_ops = {
	.ndo_open = seth_open,
	.ndo_stop = seth_close,
	.ndo_start_xmit = seth_start_xmit,
	.ndo_get_stats = seth_get_stats,
	.ndo_tx_timeout = seth_tx_timeout,
};

static int seth_parse_dt(struct seth_init_data **init, struct device *dev)
{
	struct seth_init_data *pdata = NULL;
	struct device_node *np = dev->of_node;
	int ret, dev_id;
	u32 data;

	pdata = devm_kzalloc(dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return -ENOMEM;

	pdata->name = devm_kzalloc(dev, SETH_NAME_SIZE, GFP_KERNEL);
	if (!pdata->name)
		return -ENOMEM;

	dev_id = of_alias_get_id(np, "seth");
	if (dev_id < 0) {
		dev_err(dev, "failed to get seth device id, ret= %d\n", dev_id);
		ret = dev_id;
		goto error;
	}
	snprintf(pdata->name, SETH_NAME_SIZE, "seth_lte%d", dev_id);

	ret = of_property_read_u32(
		np,
		"sprd,dst",
		&data);
	if (ret)
		goto error;

	pdata->dst = (u8)data;

	ret = of_property_read_u32(np, "sprd,channel", &data);
	if (ret)
		goto error;

	pdata->channel = (u8)data;

	ret = of_property_read_u32(
		np,
		"sprd,blknum",
		&pdata->blocknum);
	if (ret)
		goto error;

#ifdef CONFIG_SBLOCK_SHARE_BLOCKS

	ret = of_property_read_u32(
		np,
		"sprd,poolsize",
		&pdata->poolsize);
	if (ret)
		goto error;
#endif
	*init = pdata;
	return 0;
error:
	return ret;
}

static void seth_setup(struct net_device *dev)
{
	ether_setup(dev);
	/* avoid mdns to be send */
	dev->flags &= ~(IFF_BROADCAST | IFF_MULTICAST);
}

static int seth_probe(struct platform_device *pdev)
{
	struct seth_init_data *pdata = pdev->dev.platform_data;
	struct net_device *netdev;
	struct seth *seth;
	char ifname[IFNAMSIZ];
	int ret;

	if (pdev->dev.of_node && !pdata) {
		ret = seth_parse_dt(&pdata, &pdev->dev);
		if (ret) {
			dev_err(
				&pdev->dev,
				"failed to parse seth device tree, ret= %d\n",
				ret);
			return ret;
		}
	}
	dev_dbg(&pdev->dev, "after parse dt, name=%s, dst=%u, channel=%u, blocknum=%u\n",
		pdata->name, pdata->dst, pdata->channel, pdata->blocknum);

	if (pdata->name[0])
		strlcpy(ifname, pdata->name, IFNAMSIZ);
	else
		strcpy(ifname, "veth%d");

	netdev = alloc_netdev(
		sizeof(struct seth),
		ifname,
		NET_NAME_UNKNOWN,
		seth_setup);

	if (!netdev) {
		dev_err(&pdev->dev, "alloc_netdev() failed.\n");
		return -ENOMEM;
	}
	/*
	 * If net_device's type is ARPHRD_ETHER, the ipv6 interface identifier
	 * specified by the network will be covered by addrconf_ifid_eui48,
	 * this will casue ipv6 fail in some test environment. So set the seth
	 * net_device's type to ARPHRD_RAWIP here.
	 */
	netdev->type = ARPHRD_RAWIP;

	seth = netdev_priv(netdev);
	seth->pdata = pdata;
	seth->netdev = netdev;
	seth->state = DEV_OFF;

	/*
	 * Zero-copy solution: rawip
	 * non-zero copy solution: non-rawip
	 */
#ifdef CONFIG_SPRD_SIPC_SETH_RAWIP
	seth->is_rawip = 1;
#else
	seth->is_rawip = 0;
#endif
	atomic_set(&seth->rx_busy, 0);
	atomic_set(&seth->txpending, 0);

	init_timer(&seth->rx_timer);
	init_timer(&seth->tx_timer);
	seth_dt_stats_init(&seth->dt_stats);
	netdev->netdev_ops = &seth_ops;
	netdev->watchdog_timeo = 1 * HZ;
	netdev->irq = 0;
	netdev->dma = 0;

	random_ether_addr(netdev->dev_addr);

	netif_napi_add(
		netdev,
		&seth->napi,
		seth_rx_poll_handler,
		SETH_NAPI_WEIGHT);

	ret = SBLOCK_CREATE(
		pdata->dst, pdata->channel,
		pdata->blocknum, SETH_BLOCK_SIZE, pdata->poolsize,
		pdata->blocknum, SETH_BLOCK_SIZE, pdata->poolsize);
	if (ret) {
		dev_err(&pdev->dev, "create sblock failed (%d)\n", ret);
		netif_napi_del(&seth->napi);
		free_netdev(netdev);
		return ret;
	}

	ret = SBLOCK_REGISTER_NOTIFIER(
		pdata->dst,
		pdata->channel,
		seth_handler,
		seth);

	if (ret) {
		dev_err(&pdev->dev, "regitster notifier failed (%d)\n", ret);
		netif_napi_del(&seth->napi);
		free_netdev(netdev);
		SBLOCK_DESTROY(pdata->dst, pdata->channel);
		return ret;
	}

	/* Register new Ethernet interface */
	ret = register_netdev(netdev);
	if (ret) {
		dev_err(&pdev->dev, "register_netdev() failed (%d)\n", ret);
		netif_napi_del(&seth->napi);
		free_netdev(netdev);
		SBLOCK_DESTROY(pdata->dst, pdata->channel);
		return ret;
	}

	/* Set link as disconnected */
	netif_carrier_off(netdev);

	platform_set_drvdata(pdev, seth);
	seth_debugfs_mknod(root, (void *)seth);
	return 0;
}

/* Cleanup Ethernet device driver. */
static int seth_remove(struct platform_device *pdev)
{
	struct seth *seth = platform_get_drvdata(pdev);
	struct seth_init_data *pdata = seth->pdata;

	netif_napi_del(&seth->napi);
	del_timer_sync(&seth->rx_timer);
	del_timer_sync(&seth->tx_timer);
	SBLOCK_DESTROY(pdata->dst, pdata->channel);
	unregister_netdev(seth->netdev);
	free_netdev(seth->netdev);

	platform_set_drvdata(pdev, NULL);

	return 0;
}

static const struct of_device_id seth_match_table[] = {
	{ .compatible = "sprd,seth"},
	{ }
};

static struct platform_driver seth_driver = {
	.probe = seth_probe,
	.remove = seth_remove,
	.driver = {
		.owner = THIS_MODULE,
		.name = "seth",
		.of_match_table = seth_match_table
	}
};

static int seth_debug_show(struct seq_file *m, void *v)
{
	struct seth *seth = (struct seth *)(m->private);
	struct seth_dtrans_stats *stats;
	struct seth_init_data *pdata;

	if (!seth)
		return -EINVAL;

	pdata = seth->pdata;
	stats = &seth->dt_stats;

	seq_puts(m, "******************************************************************\n");
	seq_printf(
		m, "DEVICE: %s, state %d, NET_SKB_PAD %u\n",
		pdata->name,
		seth->state,
		NET_SKB_PAD);
	seq_puts(m, "\nRX statistics:\n");
	seq_printf(
		m, "rx_pkt_max=%u, rx_pkt_min=%u, rx_sum=%u, rx_cnt=%u\n",
		stats->rx_pkt_max,
		stats->rx_pkt_min,
		stats->rx_sum,
		stats->rx_cnt);
	seq_printf(
		m, "rx_alloc_fails=%u, rx_busy=%d\n",
		stats->rx_alloc_fails,
		atomic_read(&seth->rx_busy));

	seq_puts(m, "\nTX statistics:\n");
	seq_printf(
		m, "tx_pkt_max=%u, tx_pkt_min=%u, tx_sum=%u, tx_cnt=%u\n",
		stats->tx_pkt_max,
		stats->tx_pkt_min,
		stats->tx_sum,
		stats->tx_cnt);
	seq_printf(
		m, "tx_ping_cnt=%u, tx_ack_cnt=%u\n",
		stats->tx_ping_cnt, stats->tx_ack_cnt);
	seq_puts(m, "******************************************************************\n");
	return 0;
}

static int seth_debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, seth_debug_show, inode->i_private);
}

static const struct file_operations seth_debug_fops = {
	.open = seth_debug_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int seth_debugfs_mknod(void *root, void *data)
{
	struct seth *seth = (struct seth *)data;
	struct seth_init_data *pdata;

	if (!seth)
		return -ENODEV;

	pdata = seth->pdata;

	if (!root)
		return -ENXIO;

	debugfs_create_file(
		pdata->name,
		0444,
		(struct dentry *)root,
		data,
		&seth_debug_fops);

	return 0;
}

static int debugfs_gro_enable_get(void *data, u64 *val)
{
	*val = gro_enable;
	return 0;
}

static int debugfs_gro_enable_set(void *data, u64 val)
{
	gro_enable = (u32)val;
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(fops_gro_enable,
			debugfs_gro_enable_get,
			debugfs_gro_enable_set,
			"%llu\n");

static int __init seth_debugfs_init(void)
{
	root = debugfs_create_dir("seth", NULL);
	if (!root)
		return -ENODEV;

	debugfs_create_file("gro_enable",
			    0600,
			    root,
			    &gro_enable,
			    &fops_gro_enable);

	return 0;
}

static int __init seth_init(void)
{
	seth_debugfs_init();
	return platform_driver_register(&seth_driver);
}

static void __exit seth_exit(void)
{
	platform_driver_unregister(&seth_driver);
}

module_init(seth_init);
module_exit(seth_exit);

MODULE_AUTHOR("Qiu Yi");
MODULE_DESCRIPTION("Spreadtrum Ethernet device driver");
MODULE_LICENSE("GPL");
