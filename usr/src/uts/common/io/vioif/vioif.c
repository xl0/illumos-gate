/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Based on the NetBSD virtio driver by Minoura Makoto. */
/*
 * Copyright (c) 2010 Minoura Makoto.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ksynch.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/pci.h>
#include <sys/ethernet.h>

/* Please export sys/vlan.h as part of ddi */
// #include <sys/vlan.h>
#define	VLAN_TAGSZ 4

#include <sys/dlpi.h>
#include <sys/taskq.h>
#include <sys/cyclic.h>

#include <sys/pattr.h>
#include <sys/strsun.h>

#include <sys/random.h>
#include <sys/sysmacros.h>
#include <sys/stream.h>

#include <sys/mac.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>

#include "virtiovar.h"
#include "virtioreg.h"

/* Configuration registers */
#define	VIRTIO_NET_CONFIG_MAC		0 /* 8bit x 6byte */
#define	VIRTIO_NET_CONFIG_STATUS	6 /* 16bit */

/* Feature bits */
#define	VIRTIO_NET_F_CSUM	(1 << 0) /* Host handles pkts w/ partial csum */
#define	VIRTIO_NET_F_GUEST_CSUM	(1 << 1) /* Guest handles pkts w/ part csum */
#define	VIRTIO_NET_F_MAC	(1 << 5) /* Host has given MAC address. */
#define	VIRTIO_NET_F_GSO	(1 << 6) /* Host handles pkts w/ any GSO type */
#define	VIRTIO_NET_F_GUEST_TSO4	(1 << 7) /* Guest can handle TSOv4 in. */
#define	VIRTIO_NET_F_GUEST_TSO6	(1 << 8) /* Guest can handle TSOv6 in. */
#define	VIRTIO_NET_F_GUEST_ECN	(1 << 9) /* Guest can handle TSO[6] w/ ECN in */
#define	VIRTIO_NET_F_GUEST_UFO	(1 << 10) /* Guest can handle UFO in. */
#define	VIRTIO_NET_F_HOST_TSO4	(1 << 11) /* Host can handle TSOv4 in. */
#define	VIRTIO_NET_F_HOST_TSO6	(1 << 12) /* Host can handle TSOv6 in. */
#define	VIRTIO_NET_F_HOST_ECN	(1 << 13) /* Host can handle TSO[6] w/ ECN in */
#define	VIRTIO_NET_F_HOST_UFO	(1 << 14) /* Host can handle UFO in. */
#define	VIRTIO_NET_F_MRG_RXBUF	(1 << 15) /* Host can merge receive buffers. */
#define	VIRTIO_NET_F_STATUS	(1 << 16) /* Config.status available */
#define	VIRTIO_NET_F_CTRL_VQ	(1 << 17) /* Control channel available */
#define	VIRTIO_NET_F_CTRL_RX	(1 << 18) /* Control channel RX mode support */
#define	VIRTIO_NET_F_CTRL_VLAN	(1 << 19) /* Control channel VLAN filtering */
#define	VIRTIO_NET_F_CTRL_RX_EXTRA (1 << 20) /* Extra RX mode control support */

/* Status */
#define	VIRTIO_NET_S_LINK_UP	1

/* Packet header structure */
struct virtio_net_hdr {
	uint8_t		flags;
	uint8_t		gso_type;
	uint16_t	hdr_len;
	uint16_t	gso_size;
	uint16_t	csum_start;
	uint16_t	csum_offset;
};

#define	VIRTIO_NET_HDR_F_NEEDS_CSUM	1 /* flags */
#define	VIRTIO_NET_HDR_GSO_NONE		0 /* gso_type */
#define	VIRTIO_NET_HDR_GSO_TCPV4	1 /* gso_type */
#define	VIRTIO_NET_HDR_GSO_UDP		3 /* gso_type */
#define	VIRTIO_NET_HDR_GSO_TCPV6	4 /* gso_type */
#define	VIRTIO_NET_HDR_GSO_ECN		0x80 /* gso_type, |'ed */

#define ETHER_HEADER_LEN		sizeof (struct ether_header)
#define	VIRTIO_NET_MAX_GSO_LEN		(65536 + ETHER_HEADER_LEN)

/* Control virtqueue */
struct virtio_net_ctrl_cmd {
	uint8_t	class;
	uint8_t	command;
} __packed;

#define	VIRTIO_NET_CTRL_RX		0
#define	VIRTIO_NET_CTRL_RX_PROMISC	0
#define	VIRTIO_NET_CTRL_RX_ALLMULTI	1

#define	VIRTIO_NET_CTRL_MAC		1
#define	VIRTIO_NET_CTRL_MAC_TABLE_SET	0

#define	VIRTIO_NET_CTRL_VLAN		2
#define	VIRTIO_NET_CTRL_VLAN_ADD	0
#define	VIRTIO_NET_CTRL_VLAN_DEL	1

struct virtio_net_ctrl_status {
	uint8_t	ack;
} __packed;

struct virtio_net_ctrl_rx {
	uint8_t	onoff;
} __packed;

struct virtio_net_ctrl_mac_tbl {
	uint32_t nentries;
	uint8_t macs[][ETHERADDRL];
} __packed;

struct virtio_net_ctrl_vlan {
	uint16_t id;
} __packed;

static int vioif_quiesce(dev_info_t *);
static int vioif_attach(dev_info_t *, ddi_attach_cmd_t);
static int vioif_detach(dev_info_t *, ddi_detach_cmd_t);

DDI_DEFINE_STREAM_OPS(vioif_ops,
	nulldev,		/* identify */
	nulldev,		/* probe */
	vioif_attach,		/* attach */
	vioif_detach,		/* detach */
	nodev,			/* reset */
	NULL,			/* cb_ops */
	D_MP,			/* bus_ops */
	NULL,			/* power */
	vioif_quiesce		/* quiesce */
);

static char vioif_ident[] = "VirtIO ethernet driver";

/* Standard Module linkage initialization for a Streams driver */
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	vioif_ident,		/* short description */
	&vioif_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{
		(void *)&modldrv,
		NULL,
	},
};

ddi_device_acc_attr_t vioif_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,	/* virtio is always native byte order */
	DDI_STORECACHING_OK_ACC,
	DDI_DEFAULT_ACC
};


/*
 * A vioif_buf can carry an "inline" buffer (for small pakets) and
 * a bigger, "mapped" buffer used for bigger packets. Both are optional, e.g.
 * an rx vioif_buf carries only the "mapped", buffer to be able to hold GRO
 * packets. For large packets, the rx vioif_buf is loaned upstream, while
 * smaller packets get copied and the buffer is reused immediately.
 *
 * A tx vioif_buf always carries an inline buffer, which is used to hold the
 * data in case we send a small packet. Bigger packets are mapped, and linked
 * using the "mapped buffer" fields. They are sent out using
 * indirect virtio queue entries.
 */
struct vioif_buf {
	struct vioif_softc	*b_sc;
	frtn_t			b_frtn;
	/* Pointer to a message block, used for tx only. */
	mblk_t			*b_mp;

	/* inline buffer */
	caddr_t			b_buf;
	ddi_dma_handle_t	b_dmah;
	ddi_acc_handle_t	b_acch;
	ddi_dma_cookie_t	b_dmac;

	/* mapped buffer */
	caddr_t			b_mapped_buf;
	ddi_dma_handle_t	b_mapped_dmah;
	ddi_acc_handle_t	b_mapped_acch;
	ddi_dma_cookie_t	b_mapped_dmac;
	unsigned int		b_mapped_ncookies;
};

struct vioif_softc {
	dev_info_t		*sc_dev; /* mirrors virtio_softc->sc_dev */
	struct virtio_softc	sc_virtio;

	mac_handle_t sc_mac_handle;
	mac_register_t *sc_macp;

	struct virtqueue	*sc_rx_vq;
	struct virtqueue	*sc_tx_vq;
	struct virtqueue	*sc_ctrl_vq;

	unsigned int		sc_stopped:1;
	unsigned int		sc_tx_stopped:1;

	/* Feature bits. */
	unsigned int 		sc_rx_csum;
	unsigned int 		sc_tx_csum;

	int 			sc_mtu;
	uint8_t			sc_mac[ETHERADDRL];
	/*
	 * For rx buffers, we keep a pointer array, because the buffers
	 * can be loaned upstream, and we have to repopulate the array with
	 * new members.
	 */
	struct vioif_buf	**sc_rxbufs;

	/*
	 * For tx , we just allocate an array of buffers. The packet can
	 * either be copied into buf[i].b_buf, or the buffer could be used
	 * to map the packet */
	struct vioif_buf	*sc_txbufs;

	kstat_t			*sc_intrstat;
	/*
	 * We "loan" the buffers upstream and reuse them after they are
	 * freed. This lets us avoid allocations in the hot path.
	 */
	kmem_cache_t		*sc_rxbuf_cache;
	ulong_t			sc_rxloan;

	/* Copying small packets turns out to be faster then mapping them. */
	unsigned int		sc_rxcopy_thresh;
	unsigned int		sc_txcopy_thresh;
};

#define	ETHERVLANMTU    (ETHERMAX + 4)

#define	DEFAULT_MTU 	ETHERMTU
#define	MAX_MTU 	65535

/*
 * We win a bit on header alignment, but the host wins a lot
 * more on moving aligned buffers. Might need more thought.
 */
#define	VIOIF_IP_ALIGN 0


/* Maximum number of indirect descriptors, somewhat arbitrary. */
#define VIOIF_INDIRECT_MAX 128

/*
 * Yeah, we spend 8M per device. Turns out, there is no point
 * being smart and using merged rx buffers (VIRTIO_NET_F_MRG_RXBUF),
 * because vhost does not support them, and we expect to be used with
 * vhost in production environment.
 */
/* The buffer keeps both the packet data and the virtio_net_header. */
#define VIOIF_RX_SIZE (VIRTIO_NET_MAX_GSO_LEN + sizeof (struct virtio_net_hdr))

/*
 * We pre-allocate a reasonably large buffer to copy small packets
 * there. Bigger packets are mapped, packets with multiple
 * cookies are mapped as indirect buffers.
 */
#define	VIOIF_TX_INLINE_SIZE 2048

/* Native queue size for all queues */
#define	VIOIF_RX_QLEN 0
#define	VIOIF_TX_QLEN 0
#define	VIOIF_CTRL_QLEN 0

/* Add up to ddi? */
static ddi_dma_cookie_t *vioif_dma_curr_cookie(ddi_dma_handle_t dmah)
{
	ddi_dma_impl_t *dmah_impl = (void *) dmah;
	ASSERT(dmah_impl->dmai_cookie);
	return (dmah_impl->dmai_cookie);
}

static void vioif_dma_reset_cookie(ddi_dma_handle_t dmah,
    ddi_dma_cookie_t *dmac)
{
	ddi_dma_impl_t *dmah_impl = (void *) dmah;
	dmah_impl->dmai_cookie = dmac;
}

static void vioif_debug_cookies(ddi_dma_handle_t dmah,
    ddi_dma_cookie_t dmac,
    unsigned int ncookies)
{
	ddi_dma_impl_t *dmah_impl = (void *) dmah;
	ddi_dma_cookie_t *first_extra_dmac;
	int i;


	cmn_err(CE_NOTE, "^%d: laddr = 0x%" PRIx64 ", size = %ld",
		i, dmac.dmac_laddress, dmac.dmac_size);

	first_extra_dmac = vioif_dma_curr_cookie(dmah);

	for (i = 0; i < ncookies - 1; i++) {
		ddi_dma_nextcookie(dmah, &dmac);
		cmn_err(CE_NOTE, "^%d: laddr = 0x%" PRIx64 ", size = %ld",
			i, dmac.dmac_laddress, dmac.dmac_size);
	}

	vioif_dma_reset_cookie(dmah, first_extra_dmac);
}

static link_state_t
vioif_link_state(struct vioif_softc *sc)
{
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_STATUS) {
		if (virtio_read_device_config_2(&sc->sc_virtio,
		    VIRTIO_NET_CONFIG_STATUS) & VIRTIO_NET_S_LINK_UP) {

			dev_err(sc->sc_dev, CE_NOTE, "Link up\n");
			return (LINK_STATE_UP);
		} else {
			dev_err(sc->sc_dev, CE_NOTE, "Link down\n");
			return (LINK_STATE_DOWN);
		}
	}

	dev_err(sc->sc_dev, CE_NOTE, "Link assumed up\n");

	return (LINK_STATE_UP);
}

static ddi_dma_attr_t vioif_inline_buf_dma_attr = {
	DMA_ATTR_V0,		/* Version number */
	0,			/* low address */
	0xFFFFFFFFFFFFFFFF,	/* high address */
	0xFFFFFFFF,		/* counter register max */
	1,			/* page alignment */
	1,			/* burst sizes: 1 - 32 */
	1,			/* minimum transfer size */
	0xFFFFFFFF,		/* max transfer size */
	0xFFFFFFFFFFFFFFF,	/* address register max */
	1,			/* scatter-gather capacity */
	1,			/* device operates on bytes */
	0,			/* attr flag: set to 0 */
};

static ddi_dma_attr_t vioif_mapped_buf_dma_attr = {
	DMA_ATTR_V0,		/* Version number */
	0,			/* low address */
	0xFFFFFFFFFFFFFFFF,	/* high address */
	0xFFFFFFFF,		/* counter register max */
	1,			/* page alignment */
	1,			/* burst sizes: 1 - 32 */
	1,			/* minimum transfer size */
	0xFFFFFFFF,		/* max transfer size */
	0xFFFFFFFFFFFFFFF,	/* address register max */

	/* One entry is used for the virtio_net_hdr on the tx path */
	VIOIF_INDIRECT_MAX - 1,	/* scatter-gather capacity */
	1,			/* device operates on bytes */
	0,			/* attr flag: set to 0 */
};

static ddi_device_acc_attr_t vioif_bufattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STORECACHING_OK_ACC,
	DDI_DEFAULT_ACC 
};

static void vioif_rx_free(caddr_t free_arg)
{
	struct vioif_buf *buf = (void *) free_arg;
	struct vioif_softc *sc = buf->b_sc;

	kmem_cache_free(sc->sc_rxbuf_cache, buf);
	atomic_dec_ulong(&sc->sc_rxloan);
}

/* ARGSUSED */
static int vioif_rx_construct(void *buffer, void *user_arg, int kmflags)
{
	struct vioif_softc *sc = user_arg;
	struct vioif_buf *buf = buffer;
	unsigned int nsegments;
	size_t len;

	/* We don't allocate the "inline" buffer, only the mapped one. */

	if (ddi_dma_alloc_handle(sc->sc_dev, &vioif_mapped_buf_dma_attr,
	    DDI_DMA_SLEEP, NULL, &buf->b_mapped_dmah)) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Can't allocate dma handle for rx buffer");
		goto exit_handle;
	}

	if (ddi_dma_mem_alloc(buf->b_mapped_dmah,
	    VIOIF_RX_SIZE + sizeof (struct virtio_net_hdr),
	    &vioif_bufattr, DDI_DMA_STREAMING, DDI_DMA_SLEEP,
	    NULL, &buf->b_mapped_buf, &len, &buf->b_mapped_acch)) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Can't allocate rx buffer");
		goto exit_alloc;
	}
	ASSERT(len >= VIOIF_RX_SIZE);

	if (ddi_dma_addr_bind_handle(buf->b_mapped_dmah, NULL,
	    buf->b_mapped_buf, len, DDI_DMA_READ | DDI_DMA_STREAMING,
	    DDI_DMA_SLEEP, NULL, &buf->b_mapped_dmac,
	    &buf->b_mapped_ncookies)) {
		dev_err(sc->sc_dev, CE_WARN, "Can't bind tx buffer");

		goto exit_bind;
	}

	ASSERT(buf->b_mapped_ncookies <= VIOIF_INDIRECT_MAX);

	buf->b_sc = sc;
	buf->b_frtn.free_arg = (void *) buf;
	buf->b_frtn.free_func = vioif_rx_free;

	return (0);
exit_bind:
	ddi_dma_mem_free(&buf->b_mapped_acch);
exit_alloc:
	ddi_dma_free_handle(&buf->b_mapped_dmah);
exit_handle:

	return (ENOMEM);
}

/* ARGSUSED */
static void vioif_rx_destruct(void *buffer, void *user_arg)
{
	struct vioif_buf *buf = buffer;

	ASSERT(buf->b_mapped_acch);
	ASSERT(buf->b_mapped_dmah);

	(void) ddi_dma_unbind_handle(buf->b_mapped_dmah);
	ddi_dma_mem_free(&buf->b_mapped_acch);
	ddi_dma_free_handle(&buf->b_mapped_dmah);
}

static void
vioif_free_mems(struct vioif_softc *sc)
{
	int i;

	for (i = 0; i < sc->sc_tx_vq->vq_num; i++) {
		struct vioif_buf *buf = &sc->sc_txbufs[i];

		ASSERT(buf->b_acch);
		ASSERT(buf->b_dmah);

		(void) ddi_dma_unbind_handle(buf->b_dmah);
		ddi_dma_mem_free(&buf->b_acch);
		ddi_dma_free_handle(&buf->b_dmah);
	}

	kmem_free(sc->sc_txbufs, sizeof (struct vioif_buf) *
	    sc->sc_tx_vq->vq_num);

	for (i = 0; i < sc->sc_rx_vq->vq_num; i++) {
		struct vioif_buf *buf = sc->sc_rxbufs[i];

		if (buf)
			kmem_cache_free(sc->sc_rxbuf_cache, buf);
	}
	kmem_free(sc->sc_rxbufs, sizeof (struct vioif_buf *) *
	    sc->sc_rx_vq->vq_num);
}

static int
vioif_alloc_mems(struct vioif_softc *sc)
{
	int i, txqsize, rxqsize;
	size_t len;
	ddi_dma_cookie_t dmac;
	unsigned int nsegments;

	txqsize = sc->sc_tx_vq->vq_num;
	rxqsize = sc->sc_rx_vq->vq_num;

	sc->sc_txbufs = kmem_zalloc(sizeof (struct vioif_buf) * txqsize,
	    KM_SLEEP);
	if (!sc->sc_txbufs) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Failed to allocate the tx buffers array");
		goto exit_txalloc;
	}

	/*
	 * We don't allocate the rx vioif_buffs, just the pointers, as
	 * rx vioif_bufs can be loaned upstream, and we don't know the
	 * total number we need.
	 */
	sc->sc_rxbufs = kmem_zalloc(sizeof (struct vioif_buf *) * rxqsize,
	    KM_SLEEP);
	if (!sc->sc_rxbufs) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Failed to allocate the rx buffers pointer array");
		goto exit_rxalloc;
	}

	for (i = 0; i < txqsize; i++) {
		struct vioif_buf *buf = &sc->sc_txbufs[i];

		/* Allocate and bind an inline buffer and a DMA hande. */

		if (ddi_dma_alloc_handle(sc->sc_dev,
		    &vioif_inline_buf_dma_attr,
		    DDI_DMA_SLEEP, NULL, &buf->b_dmah)) {

			dev_err(sc->sc_dev, CE_WARN,
			    "Can't allocate dma handle for tx buffer %d", i);
			goto exit_tx;
		}

		if (ddi_dma_mem_alloc(buf->b_dmah, VIOIF_TX_INLINE_SIZE,
		    &vioif_bufattr, DDI_DMA_STREAMING, DDI_DMA_SLEEP,
		    NULL, &buf->b_buf, &len, &buf->b_acch)) {

			dev_err(sc->sc_dev, CE_WARN,
			    "Can't allocate tx buffer %d", i);
			goto exit_tx;
		}
		ASSERT(len >= VIOIF_TX_INLINE_SIZE);

		if (ddi_dma_addr_bind_handle(buf->b_dmah, NULL, buf->b_buf,
		    len, DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_SLEEP,
		    NULL, &dmac, &nsegments)) {

			dev_err(sc->sc_dev, CE_WARN,
			    "Can't bind tx buffer %d", i);
			goto exit_tx;
		}

		/* We asked for a single segment */
		ASSERT(nsegments == 1);
		buf->b_dmac = dmac;

		/* Allocate a handle for the mapped buffer. */
		if (ddi_dma_alloc_handle(sc->sc_dev,
		    &vioif_mapped_buf_dma_attr,
		    DDI_DMA_SLEEP, NULL, &buf->b_mapped_dmah)) {
			dev_err(sc->sc_dev, CE_WARN,
			    "Can't allocate the mapped dma"
			    " handle for tx buffer %d", i);
			goto exit_tx;
		}
	}

	return (0);

exit_tx:
	for (i = 0; i < txqsize; i++) {
		struct vioif_buf *buf = &sc->sc_txbufs[i];

		if (buf->b_dmah)
			(void) ddi_dma_unbind_handle(buf->b_dmah);
		if (buf->b_acch)
			ddi_dma_mem_free(&buf->b_acch);
		if (buf->b_dmah)
			ddi_dma_free_handle(&buf->b_dmah);
		if (buf->b_mapped_dmah)
			ddi_dma_free_handle(&buf->b_mapped_dmah);
	}

	kmem_free(sc->sc_rxbufs, sizeof (struct vioif_buf) * rxqsize);

exit_rxalloc:
	kmem_free(sc->sc_txbufs, sizeof (struct vioif_buf) * txqsize);
exit_txalloc:
	return (ENOMEM);
}

/* ARGSUSED */
int
vioif_multicst(void *arg, boolean_t add, const uint8_t *macaddr)
{
	return (DDI_SUCCESS);
}

/* ARGSUSED */
int
vioif_promisc(void *arg, boolean_t on)
{
	return (DDI_SUCCESS);
}

/* ARGSUSED */
int
vioif_unicst(void *arg, const uint8_t *macaddr)
{
	return (DDI_FAILURE);
}

 
static int vioif_add_rx(struct vioif_softc *sc, int kmflag)
{
	struct vq_entry *ve;
	struct vioif_buf *buf;
#if 0
	ve_hdr = vq_alloc_entry(sc->sc_rx_vq);
	if (!ve_hdr) {
		/* Out of free descriptors - ring already full. */
		goto exit_hdr;
	}
#endif
	ve = vq_alloc_entry(sc->sc_rx_vq);
	if (!ve) {
		/* Out of free descriptors - ring already full. */
		goto exit_vq;
	}
	buf = sc->sc_rxbufs[ve->qe_index];

	if (!buf) {
		/* First run, allocate the buffer. */
		buf = kmem_cache_alloc(sc->sc_rxbuf_cache, kmflag);
		sc->sc_rxbufs[ve->qe_index] = buf;
	}

	/* Still nothing? Bue. */
	if (!buf) {
		dev_err(sc->sc_dev, CE_WARN, "Can't allocate rx buffer");
		goto exit_buf;
	}

	ASSERT(buf->b_mapped_ncookies >= 1);

#if 0
	cmn_err(CE_NOTE, "Adding RX buffer:");
	vioif_debug_cookies(buf->b_mapped_dmah, buf->b_mapped_dmac,
	    buf->b_mapped_ncookies);
	delay(10);
#endif
	/*
	 * For an unknown reason, the virtio_net_hdr must be placed
	 * as a separate virtio queue entry.
	 */
	virtio_ve_add_indirect_buf(ve, buf->b_mapped_dmac.dmac_laddress,
	    sizeof (struct virtio_net_hdr), B_FALSE);

	/* Add the rest of the buffer. */
	virtio_ve_add_indirect_buf(ve,
	    buf->b_mapped_dmac.dmac_laddress + sizeof (struct virtio_net_hdr),
	    buf->b_mapped_dmac.dmac_size - sizeof (struct virtio_net_hdr),
	    B_FALSE);

	/*
	 * If the buffer consists on a single cookie (unlikely for a
	 * 64-k buffer), we are done. Otherwise, add the rest of the cookies
	 * using indirect entries.
	 */
	if (buf->b_mapped_ncookies > 1) {
		ddi_dma_cookie_t *first_extra_dmac;
		ddi_dma_cookie_t dmac;
		first_extra_dmac = vioif_dma_curr_cookie(buf->b_mapped_dmah);

		ddi_dma_nextcookie(buf->b_mapped_dmah, &dmac);
		virtio_ve_add_cookie(ve, buf->b_mapped_dmah,
		    dmac, buf->b_mapped_ncookies - 1, B_FALSE);
		vioif_dma_reset_cookie(buf->b_mapped_dmah, first_extra_dmac);
	}

	virtio_push_chain(ve, B_FALSE);

	return (DDI_SUCCESS);

exit_buf:
	vq_free_entry(sc->sc_rx_vq, ve);
exit_vq:
	return (DDI_FAILURE);
}

static int vioif_populate_rx(struct vioif_softc *sc, int kmflag)
{
	int i = 0;
	int ret;

	for (;;) {
		ret = vioif_add_rx(sc, kmflag);
		if (ret)
			/*
			 * We could not allocate some memory. Try to work with
			 * what we've got.
			 */
			break;
		i++;
	}

	if (i)
		virtio_sync_vq(sc->sc_rx_vq);

	return (i);
}

static int vioif_process_rx(struct vioif_softc *sc)
{
	struct vq_entry *ve;
	struct vioif_buf *buf;

	mblk_t *mp;
	uint32_t len;

	int i = 0;

	while ((ve = virtio_pull_chain(sc->sc_rx_vq, &len))) {

		buf = sc->sc_rxbufs[ve->qe_index];
		ASSERT(buf);

		if (len < sizeof (struct virtio_net_hdr)) {
			cmn_err(CE_WARN, "Rx: Cnain too small: %u",
			    len - (uint32_t) sizeof (struct virtio_net_hdr));
			virtio_free_chain(ve);
			continue;
		}

		len -= sizeof (struct virtio_net_hdr);
		/*
		 * We copy small packets that happenned to fit into a single
		 * cookie and reuse the buffers. For bigger ones, we loan
		 * the buffers upstream.
		 */
		if (len < sc->sc_rxcopy_thresh &&
		    len == buf->b_mapped_dmac.dmac_size) {
			mp = allocb(len, 0);
			if (!mp) {
				cmn_err(CE_WARN, "Failed to allocale mblock!");
				virtio_free_chain(ve);
				break;
			}

			bcopy((char *)buf->b_mapped_buf +
			    sizeof (struct virtio_net_hdr), mp->b_rptr, len);
			mp->b_wptr = mp->b_rptr + len;

		} else {
			mp = desballoc((unsigned char *)buf->b_mapped_buf +
			    sizeof (struct virtio_net_hdr) +
			    VIOIF_IP_ALIGN, len, 0, &buf->b_frtn);
			if (!mp) {
				cmn_err(CE_WARN, "Failed to allocale mblock!");
				virtio_free_chain(ve);
				break;
			}
			mp->b_wptr = mp->b_rptr + len;

			atomic_inc_ulong(&sc->sc_rxloan);
			/*
			 * Buffer loanded, we will have to allocte a new one
			 * for this slot.
			 */
			sc->sc_rxbufs[ve->qe_index] = NULL;
		}

		virtio_free_chain(ve);
		mac_rx(sc->sc_mac_handle, NULL, mp);
		i++;
	}

	return (i);
}

static void vioif_reclaim_used_tx(struct vioif_softc *sc)
{
	struct vq_entry *ve, *tmp_ve;
	struct vioif_buf *buf;
	uint32_t len;
	mblk_t *mp;
	int i = 0;

	while ((ve = virtio_pull_chain(sc->sc_tx_vq, &len))) {
		tmp_ve = ve;

		buf = &sc->sc_txbufs[ve->qe_index];
		mp = buf->b_mp;

		do {
			buf = &sc->sc_txbufs[tmp_ve->qe_index];
			/* If mapped buffer was used. */
			if (buf->b_mp) {
				ddi_dma_unbind_handle(buf->b_mapped_dmah);
				buf->b_mp = NULL;
			}
			tmp_ve = tmp_ve->qe_next;
		} while (tmp_ve);

		virtio_free_chain(ve);

		if (mp)
			freemsg(mp);

		i++;
	}

	if (sc->sc_tx_stopped && i) {
		sc->sc_tx_stopped = 0;
		mac_tx_update(sc->sc_mac_handle);
	}
}

static boolean_t
vioif_send(struct vioif_softc *sc, mblk_t *mp)
{
	ddi_dma_cookie_t dmac;
	struct vq_entry *ve;
	struct vioif_buf *buf;
	struct vq_entry *first_ve;
	struct vq_entry *tmp_ve;
	struct virtio_net_hdr *net_header;
	struct vioif_buf *first_buf;
	size_t msg_size = 0;
	int frag_count = 0;
	mblk_t *nmp;
	int ret;
	int i;

	for (nmp = mp; nmp; nmp = nmp->b_cont) {
		size_t frag_len = MBLKL(nmp);
		if (frag_len) {
			frag_count++;
			msg_size += MBLKL(nmp);
		}
	}

	if (frag_count > 1)
		cmn_err(CE_NOTE, "frag_count = %d, size = %lu",
		    frag_count, msg_size);

	if (msg_size > MAX_MTU) {
		dev_err(sc->sc_dev, CE_WARN, "Message too big");
		freemsg(mp);
		return (B_TRUE);
	}

	first_ve = ve = vq_alloc_entry(sc->sc_tx_vq);
	if (!ve) {
		/* Out of free descriptors - try later. */
		goto exit_alloc_ve;
	}

	/* Pre-allocate entries for the extra fragments. */
	for(i = 1; i < frag_count; i++) {
		tmp_ve = vq_alloc_entry(sc->sc_tx_vq);
		if (!tmp_ve) {
			goto exit_alloc_ve;
		}
		ve->qe_next = tmp_ve;
		ve = tmp_ve;
	}

	buf = &sc->sc_txbufs[first_ve->qe_index];

	/* Use the inline buffer of the first entry for the virtio_net_hdr. */
	(void) memset(buf->b_buf, 0, sizeof (struct virtio_net_hdr));

	if (sc->sc_tx_csum) {

		uint32_t csum_start;
		uint32_t csum_stuff;
		uint32_t csum_flags;

		mac_hcksum_get(mp, &csum_start, &csum_stuff, NULL,
		    NULL, &csum_flags);

		/* They want us to do the TCP/UDP csum calculation. */
		if (csum_flags & HCK_PARTIALCKSUM) {
			struct ether_header *eth_header;
			int eth_hsize;

			/* We only asked for partial csum packets. */
			ASSERT(!(csum_flags & HCK_IPV4_HDRCKSUM));
			ASSERT(!(csum_flags & HCK_FULLCKSUM));

			eth_header = (void *) mp->b_rptr;
			if (eth_header->ether_type == htons(ETHERTYPE_VLAN)) {
				eth_hsize = sizeof (struct ether_vlan_header);
			} else {
				eth_hsize = sizeof (struct ether_header);
			}

			net_header = (struct virtio_net_hdr *)buf->b_buf;
			net_header->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
			net_header->csum_start = eth_hsize + csum_start;
			net_header->csum_offset = csum_stuff - csum_start;
		}
	}

	virtio_ve_add_indirect_buf(first_ve, buf->b_dmac.dmac_laddress,
	    sizeof (struct virtio_net_hdr), B_TRUE);

	/*
	 * We copy small packets into the inline buffer. The bigger ones
	 * get mapped using the mapped buffer.
	 */
	if (msg_size < sc->sc_txcopy_thresh) {
		/* Frees mp */
		mcopymsg(mp, buf->b_buf + sizeof (struct virtio_net_hdr));

		virtio_ve_add_indirect_buf(first_ve,
		    buf->b_dmac.dmac_laddress + sizeof (struct virtio_net_hdr),
			msg_size, B_TRUE);
	} else {
		nmp = mp;
		/* Remember the mp to free it when the packet is sent. */
		buf->b_mp = mp;
		ve = first_ve;

		while (nmp) {
			size_t len;
			len = MBLKL(nmp);
			/*
			 * The e1000g driver suggests there could be
			 * zero-length fragments.
			 */
			if (len == 0) {
				nmp = nmp->b_cont;
				continue;
			}
			ASSERT(ve);
			buf = &sc->sc_txbufs[ve->qe_index];

			ret = ddi_dma_addr_bind_handle(buf->b_mapped_dmah,
			   NULL, (caddr_t)nmp->b_rptr, len,
			   DDI_DMA_WRITE | DDI_DMA_STREAMING,
			   DDI_DMA_DONTWAIT, NULL, &dmac,
			   &buf->b_mapped_ncookies);

			virtio_ve_add_cookie(ve, buf->b_mapped_dmah, dmac,
			    buf->b_mapped_ncookies, B_TRUE);

			nmp = nmp->b_cont;
			ve = ve->qe_next;
		}
	}

	virtio_push_chain(first_ve, B_TRUE);

	return (B_TRUE);

exit_alloc_ve:
	ve = first_ve;
	while (ve) {
		tmp_ve = ve->qe_next;
		vq_free_entry(sc->sc_tx_vq, ve);
		ve = tmp_ve;
	};

	freemsg(mp);
	return (B_TRUE);
}

mblk_t *
vioif_tx(void *arg, mblk_t *mp)
{
	struct vioif_softc *sc = arg;
	mblk_t	*nmp;

	while (mp != NULL) {
		nmp = mp->b_next;
		mp->b_next = NULL;

		if (!vioif_send(sc, mp)) {
			sc->sc_tx_stopped = 1;
			mp->b_next = nmp;
			break;
		}
		mp = nmp;
	}

	return (mp);
}

int
vioif_start(void *arg)
{
	struct vioif_softc *sc = arg;

	mac_link_update(sc->sc_mac_handle,
	    vioif_link_state(sc));

	virtio_start_vq_intr(sc->sc_rx_vq);

	return (DDI_SUCCESS);
}

void
vioif_stop(void *arg)
{
	struct vioif_softc *sc = arg;

	virtio_stop_vq_intr(sc->sc_rx_vq);
}

/* ARGSUSED */
static int
vioif_stat(void *arg, uint_t stat, uint64_t *val)
{
	switch (stat) {
		case MAC_STAT_IFSPEED:
			/* 1 Gbit */
			*val = 1000000000ULL;
			break;
		case ETHER_STAT_LINK_DUPLEX:
			*val = LINK_DUPLEX_FULL;
			break;

		default:
			return (ENOTSUP);
	}

	return (DDI_SUCCESS);
}

#if 0
static int
vioif_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
		    uint_t pr_valsize, const void *pr_val)
{
	struct vioif_softc *sc = arg;
	const uint32_t *new_mtu;
	int err;

	switch (pr_num) {
		case MAC_PROP_MTU:
			new_mtu = pr_val;

			if (*new_mtu > MAX_MTU) {
				dev_err(sc->sc_dev, CE_WARN,
				    "Requested mtu (%d) out of range",
				    *new_mtu);
				return (EINVAL);
			}

			err = mac_maxsdu_update(sc->sc_mac_handle, *new_mtu);
			if (err) {
				dev_err(sc->sc_dev, CE_WARN,
				    "Failed to set the requested mtu (%d)",
				    *new_mtu);
				return (err);
			}

			break;
		default:
			return (ENOTSUP);
	}

	return (0);
}


static int
vioif_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
		    uint_t pr_valsize, void *pr_val)
{
	return (ENOTSUP);
}

static void
vioif_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
	mac_prop_info_handle_t prh)
{
	switch (pr_num) {
		case MAC_PROP_MTU:
			mac_prop_info_set_range_uint32(prh, ETHERMIN, MAX_MTU);
			break;
		default:
			break;
	}
}
#endif

static boolean_t
vioif_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	struct vioif_softc *sc = arg;

	switch (cap) {
	case MAC_CAPAB_HCKSUM:
		if (sc->sc_tx_csum) {
			uint32_t *txflags = cap_data;

			*txflags = HCKSUM_INET_PARTIAL;
			return (B_TRUE);
		}
		return (B_FALSE);
	}

	return (B_FALSE);
}

static mac_callbacks_t vioif_m_callbacks = {
	.mc_callbacks	= MC_GETCAPAB,
	.mc_getstat	= vioif_stat,
	.mc_start	= vioif_start,
	.mc_stop	= vioif_stop,
	.mc_setpromisc	= vioif_promisc,
	.mc_multicst	= vioif_multicst,
	.mc_unicst	= vioif_unicst,
	.mc_tx		= vioif_tx,
	/* Optional callbacks */
	.mc_reserved	= NULL,		/* reserved */
	.mc_ioctl	= NULL,		/* mc_ioctl */
	.mc_getcapab	= vioif_getcapab,		/* mc_getcapab */
	.mc_open	= NULL,		/* mc_open */
	.mc_close	= NULL,		/* mc_close */
	.mc_setprop	= NULL,
	.mc_getprop	= NULL,
	.mc_propinfo	= NULL,
};

static void
vioif_show_features(struct vioif_softc *sc, const char *prefix,
		uint32_t features)
{
	char buf[512];
	char *bufp = buf;
	char *bufend = buf + sizeof (buf);

	/* LINTED E_PTRDIFF_OVERFLOW */
	bufp += snprintf(bufp, bufend - bufp, prefix);

	/* LINTED E_PTRDIFF_OVERFLOW */
	bufp += virtio_show_features(features, bufp, bufend - bufp);

	/* LINTED E_PTRDIFF_OVERFLOW */
	bufp += snprintf(bufp, bufend - bufp, "Vioif ( ");

	if (features & VIRTIO_NET_F_CSUM)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "CSUM ");
	if (features & VIRTIO_NET_F_GUEST_CSUM)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "GUEST_CSUM ");
	if (features & VIRTIO_NET_F_MAC)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "MAC ");
	if (features & VIRTIO_NET_F_GSO)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "GSO ");
	if (features & VIRTIO_NET_F_GUEST_TSO4)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "GUEST_TSO4 ");
	if (features & VIRTIO_NET_F_GUEST_TSO6)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "GUEST_TSO6 ");
	if (features & VIRTIO_NET_F_GUEST_ECN)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "GUEST_ECN ");
	if (features & VIRTIO_NET_F_GUEST_UFO)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "GUEST_UFO ");
	if (features & VIRTIO_NET_F_HOST_TSO4)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "HOST_TSO4 ");
	if (features & VIRTIO_NET_F_HOST_TSO6)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "HOST_TSO6 ");
	if (features & VIRTIO_NET_F_HOST_ECN)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "HOST_ECN ");
	if (features & VIRTIO_NET_F_HOST_UFO)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "HOST_UFO ");
	if (features & VIRTIO_NET_F_MRG_RXBUF)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "MRG_RXBUF ");
	if (features & VIRTIO_NET_F_STATUS)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "STATUS ");
	if (features & VIRTIO_NET_F_CTRL_VQ)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "CTRL_VQ ");
	if (features & VIRTIO_NET_F_CTRL_RX)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "CTRL_RX ");
	if (features & VIRTIO_NET_F_CTRL_VLAN)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "CTRL_VLAN ");
	if (features & VIRTIO_NET_F_CTRL_RX_EXTRA)
		/* LINTED E_PTRDIFF_OVERFLOW */
		bufp += snprintf(bufp, bufend - bufp, "CTRL_RX_EXTRA ");

	/* LINTED E_PTRDIFF_OVERFLOW */
	bufp += snprintf(bufp, bufend - bufp, ")");
	*bufp = '\0';

	dev_err(sc->sc_dev, CE_NOTE, "%s", buf);
}

/*
 * Find out which features are supported by the device and
 * choose which ones we wish to use.
 */
static int
vioif_dev_features(struct vioif_softc *sc)
{
	uint32_t host_features;

	host_features = virtio_negotiate_features(&sc->sc_virtio,
	    VIRTIO_NET_F_CSUM |
	    VIRTIO_NET_F_MAC |
	    VIRTIO_NET_F_STATUS |
	    VIRTIO_F_RING_INDIRECT_DESC |
	    VIRTIO_F_NOTIFY_ON_EMPTY);

	vioif_show_features(sc, "Host features: ", host_features);
	vioif_show_features(sc, "Negotiated features: ",
	    sc->sc_virtio.sc_features);

	if (!(sc->sc_virtio.sc_features & VIRTIO_F_RING_INDIRECT_DESC)) {
		dev_err(sc->sc_dev, CE_NOTE,
		    "Host does not support RING_INDIRECT_DESC, bye.");
		return (DDI_FAILURE);
	}


	return (DDI_SUCCESS);
}

static int vioif_has_feature(struct vioif_softc *sc, uint32_t feature)
{
	return (virtio_has_feature(&sc->sc_virtio, feature));
}

static void
vioif_set_mac(struct vioif_softc *sc)
{
	int i;

	for (i = 0; i < ETHERADDRL; i++) {
		virtio_write_device_config_1(&sc->sc_virtio,
		    VIRTIO_NET_CONFIG_MAC + i, sc->sc_mac[i]);
	}
}

/* Get the mac address out of the hardware, or make up one. */
static void
vioif_get_mac(struct vioif_softc *sc)
{
	int i;
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_MAC) {
		for (i = 0; i < ETHERADDRL; i++) {
			sc->sc_mac[i] = virtio_read_device_config_1(
			    &sc->sc_virtio,
			    VIRTIO_NET_CONFIG_MAC + i);
		}
		dev_err(sc->sc_dev, CE_NOTE, "Got MAC address from host: %s",
		    ether_sprintf((struct ether_addr *)sc->sc_mac));
	} else {
		/* Get a few random bytes */
		(void) random_get_pseudo_bytes(sc->sc_mac, ETHERADDRL);
		/* Make sure it's a unicast MAC */
		sc->sc_mac[0] &= ~1;
		/* Set the "locally administered" bit */
		sc->sc_mac[1] |= 2;

		vioif_set_mac(sc);

		dev_err(sc->sc_dev, CE_NOTE,
		    "Generated a random MAC address: %s",
		    ether_sprintf((struct ether_addr *)sc->sc_mac));
	}
}


/*
 * Virtqueue interrupt handlers
 */
/* ARGSUSED */
uint_t
vioif_rx_handler(caddr_t arg1, caddr_t arg2)
{
	struct virtio_softc *vsc = (void *) arg1;
	/* LINTED E_PTRDIFF_OVERFLOW */
	struct vioif_softc *sc = container_of(vsc,
	    struct vioif_softc, sc_virtio);

	(void) vioif_process_rx(sc);

	(void) vioif_populate_rx(sc, KM_NOSLEEP);

	return (DDI_INTR_CLAIMED);
}

/* ARGSUSED */
uint_t
vioif_tx_handler(caddr_t arg1, caddr_t arg2)
{
	struct virtio_softc *vsc = (void *)arg1;
	/* LINTED E_PTRDIFF_OVERFLOW */
	struct vioif_softc *sc = container_of(vsc,
	    struct vioif_softc, sc_virtio);

	vioif_reclaim_used_tx(sc);
	return (DDI_INTR_CLAIMED);
}

static int
vioif_register_ints(struct vioif_softc *sc)
{
	int ret;

	struct virtio_int_handler vioif_vq_h[] = {
		{ vioif_rx_handler },
		{ vioif_tx_handler },
		{ NULL }
	};

	ret = virtio_register_ints(&sc->sc_virtio, NULL, vioif_vq_h);

	return (ret);
}


static void vioif_check_features(struct vioif_softc *sc)
{
	if (vioif_has_feature(sc, VIRTIO_NET_F_CSUM)) {
		/* The GSO/GRO featured depend on CSUM, check them here. */

		/*
		 * Linux only checks for VIRTIO_NET_F_CSUM, so it's safe to
		 * assume that they always come together. If not, we'd like
		 * to know about it.
		 */
#if 0
		if (!vioif_has_feature(sc, VIRTIO_NET_F_GUEST_CSUM)) {
			dev_err(sc->sc_dev, CE_NOTE,
			    "CSUM but !GUEST_CSUM. This is unexpected,"
			    " not using hardware checksumming.");
			goto exit_no_guest_csum;
		}
#endif
		cmn_err(CE_NOTE, "Csum enabled.");

		sc->sc_tx_csum = 1;
		sc->sc_rx_csum = 1;
	}
	cmn_err(CE_NOTE, "Csum not enabled");

exit_no_guest_csum:
	;
}

static int
vioif_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	int ret, instance;
	struct vioif_softc *sc;
	struct virtio_softc *vsc;
	mac_register_t *macp;
	ddi_acc_handle_t pci_conf;

	instance = ddi_get_instance(devinfo);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
	case DDI_PM_RESUME:
		dev_err(devinfo, CE_WARN, "resume not supported yet");
		goto exit;

	default:
		dev_err(devinfo, CE_WARN, "cmd 0x%x unrecognized", cmd);
		goto exit;
	}

	sc = kmem_zalloc(sizeof (struct vioif_softc), KM_SLEEP);
	ddi_set_driver_private(devinfo, sc);

	vsc = &sc->sc_virtio;

	/* Duplicate for less typing */
	sc->sc_dev = devinfo;
	vsc->sc_dev = devinfo;

	/*
	 * Initialize interrupt kstat.
	 */
	sc->sc_intrstat = kstat_create("vioif", instance, "intr", "controller",
	    KSTAT_TYPE_INTR, 1, 0);
	if (sc->sc_intrstat == NULL) {
		dev_err(devinfo, CE_WARN, "kstat_create failed");
		goto exit_intrstat;
	}
	kstat_install(sc->sc_intrstat);

	/* map BAR 0 */
	ret = ddi_regs_map_setup(devinfo, 1,
	    (caddr_t *)&sc->sc_virtio.sc_io_addr,
	    0, 0, &vioif_attr, &sc->sc_virtio.sc_ioh);
	if (ret != DDI_SUCCESS) {
		dev_err(devinfo, CE_WARN, "unable to map bar 0: %d", ret);
		goto exit_map;
	}

	virtio_device_reset(&sc->sc_virtio);
	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_ACK);
	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER);

	ret = vioif_dev_features(sc);
	if (ret)
		goto exit_features;

	vsc->sc_nvqs = vioif_has_feature(sc, VIRTIO_NET_F_CTRL_VQ) ? 3 : 2;

	sc->sc_rxbuf_cache = kmem_cache_create("vioif_rx",
	    sizeof (struct vioif_buf), 0,
	    vioif_rx_construct, vioif_rx_destruct,
	    NULL, sc, NULL, KM_SLEEP);
	if (!sc->sc_rxbuf_cache) {
		cmn_err(CE_NOTE, "Can't allocate the buffer cache");
		goto exit_cache;
	}

	ret = vioif_register_ints(sc);
	if (ret) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Failed to allocate interrupt(s)!");
		goto exit_ints;
	}

	/*
	 * Register layout determined, can now access the
	 * device-speciffic bits
	 */
	vioif_get_mac(sc);

	sc->sc_rx_vq = virtio_alloc_vq(&sc->sc_virtio, 0,
	    VIOIF_RX_QLEN, VIOIF_INDIRECT_MAX, "rx");
	if (!sc->sc_rx_vq)
		goto exit_alloc1;
	virtio_stop_vq_intr(sc->sc_rx_vq);

	sc->sc_tx_vq = virtio_alloc_vq(&sc->sc_virtio, 1,
	    VIOIF_TX_QLEN, VIOIF_INDIRECT_MAX, "tx");
	if (!sc->sc_rx_vq)
		goto exit_alloc2;
	virtio_stop_vq_intr(sc->sc_tx_vq);

	if (vioif_has_feature(sc, VIRTIO_NET_F_CTRL_VQ)) {
		sc->sc_ctrl_vq = virtio_alloc_vq(&sc->sc_virtio, 2,
		    VIOIF_CTRL_QLEN, 0, "ctrl");
		if (!sc->sc_ctrl_vq) {
			goto exit_alloc3;
		}
		virtio_stop_vq_intr(sc->sc_ctrl_vq);
	}

	virtio_set_status(&sc->sc_virtio,
	    VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK);

	sc->sc_rxloan = 0;

	/* XXX Make this configurable. */
	sc->sc_rxcopy_thresh = 300;
	sc->sc_txcopy_thresh = 300;

	vioif_check_features(sc);

	if (vioif_alloc_mems(sc))
		goto exit_alloc_mems;

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		dev_err(devinfo, CE_WARN, "Failed to alocate a mac_register");
		goto exit_macalloc;
	}

	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = sc;
	macp->m_dip = devinfo;
	macp->m_src_addr = sc->sc_mac;
	macp->m_callbacks = &vioif_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = MAX_MTU/*DEFAULT_MTU*/;
	macp->m_margin = VLAN_TAGSZ;

	sc->sc_macp = macp;

	/* Pre-fill the rx ring. */
	(void) vioif_populate_rx(sc, KM_SLEEP);

	ret = mac_register(macp, &sc->sc_mac_handle);
	if (ret) {
		dev_err(devinfo, CE_WARN, "Failed to register the device");
		goto exit_register;
	}

	ret = virtio_enable_ints(&sc->sc_virtio);
	if (ret) {
		dev_err(devinfo, CE_WARN, "Failed to enable interrupts");
		goto exit_enable_ints;
	}

	return (DDI_SUCCESS);

exit_enable_ints:
	mac_unregister(sc->sc_mac_handle);
exit_register:
	mac_free(macp);
exit_macalloc:
	vioif_free_mems(sc);
exit_alloc_mems:
	virtio_release_ints(&sc->sc_virtio);
	if (sc->sc_ctrl_vq)
		virtio_free_vq(sc->sc_ctrl_vq);
exit_alloc3:
	virtio_free_vq(sc->sc_tx_vq);
exit_alloc2:
	virtio_free_vq(sc->sc_rx_vq);
exit_alloc1:
exit_ints:
	kmem_cache_destroy(sc->sc_rxbuf_cache);
exit_cache:
exit_features:
	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_FAILED);
	ddi_regs_map_free(&sc->sc_virtio.sc_ioh);
exit_intrstat:
exit_map:
	kstat_delete(sc->sc_intrstat);
	kmem_free(sc, sizeof (struct vioif_softc));
exit:
	return (DDI_FAILURE);
}

static int
vioif_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	struct vioif_softc *sc;

	if ((sc = ddi_get_driver_private(devinfo)) == NULL)
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_PM_SUSPEND:
		cmn_err(CE_WARN, "suspend not supported yet");
		return (DDI_FAILURE);

	default:
		cmn_err(CE_WARN, "cmd 0x%x unrecognized", cmd);
		return (DDI_FAILURE);
	}

	if (sc->sc_rxloan) {
		cmn_err(CE_NOTE, "Some rx buffers are still upstream, "
		    "Not detaching");
		return (DDI_FAILURE);
	}

	virtio_stop_vq_intr(sc->sc_rx_vq);
	virtio_stop_vq_intr(sc->sc_tx_vq);

	virtio_release_ints(&sc->sc_virtio);

	if (mac_unregister(sc->sc_mac_handle)) {
		return (DDI_FAILURE);
	}

	mac_free(sc->sc_macp);

	vioif_free_mems(sc);
	virtio_free_vq(sc->sc_rx_vq);
	virtio_free_vq(sc->sc_tx_vq);

	virtio_device_reset(&sc->sc_virtio);

	ddi_regs_map_free(&sc->sc_virtio.sc_ioh);

	kmem_cache_destroy(sc->sc_rxbuf_cache);
	kstat_delete(sc->sc_intrstat);
	kmem_free(sc, sizeof (struct vioif_softc));

	return (DDI_SUCCESS);
}

static int
vioif_quiesce(dev_info_t *devinfo)
{
	struct vioif_softc *sc;

	if ((sc = ddi_get_driver_private(devinfo)) == NULL)
		return (DDI_FAILURE);

	virtio_stop_vq_intr(sc->sc_rx_vq);
	virtio_stop_vq_intr(sc->sc_tx_vq);
	virtio_device_reset(&sc->sc_virtio);

	return (DDI_SUCCESS);
}

int
_init(void)
{
	int ret = 0;

	mac_init_ops(&vioif_ops, "vioif");
	if ((ret = mod_install(&modlinkage)) != DDI_SUCCESS) {
		mac_fini_ops(&vioif_ops);
		cmn_err(CE_WARN, "Unable to install the driver");
		return (ret);
	}

	return (0);
}

int
_fini(void)
{
	int ret;

	ret = mod_remove(&modlinkage);
	if (ret == DDI_SUCCESS) {
		mac_fini_ops(&vioif_ops);
	}

	return (ret);
}

int
_info(struct modinfo *pModinfo)
{
	return (mod_info(&modlinkage, pModinfo));
}
