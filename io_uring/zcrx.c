// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/dma-map-ops.h>
#include <linux/mm.h>
#include <linux/nospec.h>
#include <linux/io_uring.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff_ref.h>

#include <net/page_pool/helpers.h>
#include <net/page_pool/memory_provider.h>
#include <net/netlink.h>
#include <net/netdev_rx_queue.h>
#include <net/tcp.h>
#include <net/rps.h>

#include <trace/events/page_pool.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "kbuf.h"
#include "memmap.h"
#include "zcrx.h"
#include "rsrc.h"

#define IO_DMA_ATTR (DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING)

/*
 * Function: __io_zcrx_unmap_area
 * Purpose : Unmaps 'nr_mapped' pages from the DMA mapping for the given area.
 *           Iterates over the specified number of net_iov descriptors, unmapping each page.
 */
static void __io_zcrx_unmap_area(struct io_zcrx_ifq *ifq,
                 struct io_zcrx_area *area, int nr_mapped)
{
    int i;

    for (i = 0; i < nr_mapped; i++) {
        struct net_iov *niov = &area->nia.niovs[i];
        dma_addr_t dma;

        dma = page_pool_get_dma_addr_netmem(net_iov_to_netmem(niov));
        dma_unmap_page_attrs(ifq->dev, dma, PAGE_SIZE,
                     DMA_FROM_DEVICE, IO_DMA_ATTR);
        net_mp_niov_set_dma_addr(niov, 0);
    }
}

/*
 * Function: io_zcrx_unmap_area
 * Purpose : Public wrapper to unmap the entire area if it is currently mapped.
 */
static void io_zcrx_unmap_area(struct io_zcrx_ifq *ifq, struct io_zcrx_area *area)
{
    if (area->is_mapped)
        __io_zcrx_unmap_area(ifq, area, area->nia.num_niovs);
}

/*
 * Function: io_zcrx_map_area
 * Purpose : Maps all pages in the given area for device DMA access.
 *           Iterates over each net_iov entry, mapping the page. If mapping fails
 *           for any page, it unmaps any partially mapped pages and returns an error.
 */
static int io_zcrx_map_area(struct io_zcrx_ifq *ifq, struct io_zcrx_area *area)
{
    int i;

    for (i = 0; i < area->nia.num_niovs; i++) {
        struct net_iov *niov = &area->nia.niovs[i];
        dma_addr_t dma;

        dma = dma_map_page_attrs(ifq->dev, area->pages[i], 0, PAGE_SIZE,
                     DMA_FROM_DEVICE, IO_DMA_ATTR);
        if (dma_mapping_error(ifq->dev, dma))
            break;
        if (net_mp_niov_set_dma_addr(niov, dma)) {
            dma_unmap_page_attrs(ifq->dev, dma, PAGE_SIZE,
                         DMA_FROM_DEVICE, IO_DMA_ATTR);
            break;
        }
    }

    if (i != area->nia.num_niovs) {
        __io_zcrx_unmap_area(ifq, area, i);
        return -EINVAL;
    }

    area->is_mapped = true;
    return 0;
}

/*
 * Function: io_zcrx_sync_for_device
 * Purpose : Synchronizes the DMA buffer for device access.
 *           Ensures that the buffer is coherent for DMA if required by the device.
 */
static void io_zcrx_sync_for_device(const struct page_pool *pool,
                    struct net_iov *niov)
{
#if defined(CONFIG_HAS_DMA) && defined(CONFIG_DMA_NEED_SYNC)
    dma_addr_t dma_addr;

    if (!dma_dev_need_sync(pool->p.dev))
        return;

    dma_addr = page_pool_get_dma_addr_netmem(net_iov_to_netmem(niov));
    __dma_sync_single_for_device(pool->p.dev, dma_addr + pool->p.offset,
                     PAGE_SIZE, pool->p.dma_dir);
#endif
}

#define IO_RQ_MAX_ENTRIES       32768
#define IO_SKBS_PER_CALL_LIMIT  20

/*
 * Structure: io_zcrx_args
 * Purpose   : Holds parameters for zero‑copy receive (zcrx) operations.
 */
struct io_zcrx_args {
    struct io_kiocb     *req;
    struct io_zcrx_ifq  *ifq;
    struct socket       *sock;
    unsigned        nr_skbs;
};

/*
 * Function: io_zcrx_iov_to_area
 * Purpose : Converts a net_iov pointer to its owning io_zcrx_area.
 *           Retrieves the associated area using container_of.
 */
static inline struct io_zcrx_area *io_zcrx_iov_to_area(const struct net_iov *niov)
{
    struct net_iov_area *owner = net_iov_owner(niov);

    return container_of(owner, struct io_zcrx_area, nia);
}

/*
 * Function: io_get_user_counter
 * Purpose : Retrieves the atomic user reference counter for a given net_iov.
 */
static inline atomic_t *io_get_user_counter(struct net_iov *niov)
{
    struct io_zcrx_area *area = io_zcrx_iov_to_area(niov);

    return &area->user_refs[net_iov_idx(niov)];
}

/*
 * Function: io_zcrx_put_niov_uref
 * Purpose : Decrements the user reference counter for a net_iov.
 *           Returns false if the counter is already zero, otherwise decrements it.
 */
static bool io_zcrx_put_niov_uref(struct net_iov *niov)
{
    atomic_t *uref = io_get_user_counter(niov);

    if (unlikely(!atomic_read(uref)))
        return false;
    atomic_dec(uref);
    return true;
}

/*
 * Function: io_zcrx_get_niov_uref
 * Purpose : Increments the user reference counter for a net_iov.
 */
static void io_zcrx_get_niov_uref(struct net_iov *niov)
{
    atomic_inc(io_get_user_counter(niov));
}

/*
 * Function: io_zcrx_iov_page
 * Purpose : Returns the associated page for a net_iov descriptor.
 *           Determines the page from the io_zcrx_area using the net_iov index.
 */
static inline struct page *io_zcrx_iov_page(const struct net_iov *niov)
{
    struct io_zcrx_area *area = io_zcrx_iov_to_area(niov);

    return area->pages[net_iov_idx(niov)];
}

/*
 * Function: io_allocate_rbuf_ring
 * Purpose : Allocates and initializes the receive buffer ring for zero‑copy RX.
 *           Validates that the ring size does not exceed the provided region and maps the region.
 */
static int io_allocate_rbuf_ring(struct io_zcrx_ifq *ifq,
                 struct io_uring_zcrx_ifq_reg *reg,
                 struct io_uring_region_desc *rd)
{
    size_t off, size;
    void *ptr;
    int ret;

    off = sizeof(struct io_uring);
    size = off + sizeof(struct io_uring_zcrx_rqe) * reg->rq_entries;
    if (size > rd->size)
        return -EINVAL;

    ret = io_create_region_mmap_safe(ifq->ctx, &ifq->ctx->zcrx_region, rd,
                     IORING_MAP_OFF_ZCRX_REGION);
    if (ret < 0)
        return ret;

    ptr = io_region_get_ptr(&ifq->ctx->zcrx_region);
    ifq->rq_ring = (struct io_uring *)ptr;
    ifq->rqes = (struct io_uring_zcrx_rqe *)(ptr + off);
    return 0;
}

/*
 * Function: io_free_rbuf_ring
 * Purpose : Frees the receive buffer ring region associated with the interface queue.
 *           Resets the ring and requests pointers to NULL.
 */
static void io_free_rbuf_ring(struct io_zcrx_ifq *ifq)
{
    io_free_region(ifq->ctx, &ifq->ctx->zcrx_region);
    ifq->rq_ring = NULL;
    ifq->rqes = NULL;
}

/*
 * Function: io_zcrx_free_area
 * Purpose : Frees an allocated zero‑copy receive buffer area.
 *           Unmaps DMA if mapped, frees the freelist, niovs, user reference counters,
 *           unpins user pages, and finally frees the area structure.
 */
static void io_zcrx_free_area(struct io_zcrx_area *area)
{
    io_zcrx_unmap_area(area->ifq, area);

    kvfree(area->freelist);
    kvfree(area->nia.niovs);
    kvfree(area->user_refs);
    if (area->pages) {
        unpin_user_pages(area->pages, area->nia.num_niovs);
        kvfree(area->pages);
    }
    kfree(area);
}

/*
 * Function: io_zcrx_create_area
 * Purpose : Creates and initializes a zero‑copy receive buffer area.
 *           Validates the provided region, pins the user pages, allocates net_iov descriptors,
 *           sets up the freelist and user reference counters, and initializes area metadata.
 */
static int io_zcrx_create_area(struct io_zcrx_ifq *ifq,
                   struct io_zcrx_area **res,
                   struct io_uring_zcrx_area_reg *area_reg)
{
    struct io_zcrx_area *area;
    int i, ret, nr_pages;
    struct iovec iov;

    if (area_reg->flags || area_reg->rq_area_token)
        return -EINVAL;
    if (area_reg->__resv1 || area_reg->__resv2[0] || area_reg->__resv2[1])
        return -EINVAL;
    if (area_reg->addr & ~PAGE_MASK || area_reg->len & ~PAGE_MASK)
        return -EINVAL;

    iov.iov_base = u64_to_user_ptr(area_reg->addr);
    iov.iov_len = area_reg->len;
    ret = io_buffer_validate(&iov);
    if (ret)
        return ret;

    ret = -ENOMEM;
    area = kzalloc(sizeof(*area), GFP_KERNEL);
    if (!area)
        goto err;

    area->pages = io_pin_pages((unsigned long)area_reg->addr, area_reg->len,
                   &nr_pages);
    if (IS_ERR(area->pages)) {
        ret = PTR_ERR(area->pages);
        area->pages = NULL;
        goto err;
    }
    area->nia.num_niovs = nr_pages;

    area->nia.niovs = kvmalloc_array(nr_pages, sizeof(area->nia.niovs[0]),
                     GFP_KERNEL | __GFP_ZERO);
    if (!area->nia.niovs)
        goto err;

    area->freelist = kvmalloc_array(nr_pages, sizeof(area->freelist[0]),
                    GFP_KERNEL | __GFP_ZERO);
    if (!area->freelist)
        goto err;

    for (i = 0; i < nr_pages; i++)
        area->freelist[i] = i;

    area->user_refs = kvmalloc_array(nr_pages, sizeof(area->user_refs[0]),
                    GFP_KERNEL | __GFP_ZERO);
    if (!area->user_refs)
        goto err;

    for (i = 0; i < nr_pages; i++) {
        struct net_iov *niov = &area->nia.niovs[i];

        niov->owner = &area->nia;
        area->freelist[i] = i;
        atomic_set(&area->user_refs[i], 0);
    }

    area->free_count = nr_pages;
    area->ifq = ifq;
    /* we're only supporting one area per ifq for now */
    area->area_id = 0;
    area_reg->rq_area_token = (u64)area->area_id << IORING_ZCRX_AREA_SHIFT;
    spin_lock_init(&area->freelist_lock);
    *res = area;
    return 0;
err:
    if (area)
        io_zcrx_free_area(area);
    return ret;
}

/*
 * Function: io_zcrx_ifq_alloc
 * Purpose : Allocates and initializes a new zero‑copy RX interface queue.
 *           Sets default values and initializes locks.
 */
static struct io_zcrx_ifq *io_zcrx_ifq_alloc(struct io_ring_ctx *ctx)
{
    struct io_zcrx_ifq *ifq;

    ifq = kzalloc(sizeof(*ifq), GFP_KERNEL);
    if (!ifq)
        return NULL;

    ifq->if_rxq = -1;
    ifq->ctx = ctx;
    spin_lock_init(&ifq->lock);
    spin_lock_init(&ifq->rq_lock);
    return ifq;
}

/*
 * Function: io_zcrx_drop_netdev
 * Purpose : Drops the network device associated with the interface queue.
 *           Releases the reference on the network device if it is set.
 */
static void io_zcrx_drop_netdev(struct io_zcrx_ifq *ifq)
{
    spin_lock(&ifq->lock);
    if (ifq->netdev) {
        netdev_put(ifq->netdev, &ifq->netdev_tracker);
        ifq->netdev = NULL;
    }
    spin_unlock(&ifq->lock);
}

/*
 * Function: io_close_queue
 * Purpose : Closes the RX queue associated with the interface queue.
 *           If the queue is valid, it closes and releases references to the network device.
 */
static void io_close_queue(struct io_zcrx_ifq *ifq)
{
    struct net_device *netdev;
    netdevice_tracker netdev_tracker;
    struct pp_memory_provider_params p = {
        .mp_ops = &io_uring_pp_zc_ops,
        .mp_priv = ifq,
    };

    if (ifq->if_rxq == -1)
        return;

    spin_lock(&ifq->lock);
    netdev = ifq->netdev;
    netdev_tracker = ifq->netdev_tracker;
    ifq->netdev = NULL;
    spin_unlock(&ifq->lock);

    if (netdev) {
        net_mp_close_rxq(netdev, ifq->if_rxq, &p);
        netdev_put(netdev, &netdev_tracker);
    }
    ifq->if_rxq = -1;
}

/*
 * Function: io_zcrx_ifq_free
 * Purpose : Frees the zero‑copy RX interface queue.
 *           Closes the queue, drops the netdev, frees the associated area, device reference,
 *           release the receive buffer ring, and finally frees the ifq structure.
 */
static void io_zcrx_ifq_free(struct io_zcrx_ifq *ifq)
{
    io_close_queue(ifq);
    io_zcrx_drop_netdev(ifq);

    if (ifq->area)
        io_zcrx_free_area(ifq->area);
    if (ifq->dev)
        put_device(ifq->dev);

    io_free_rbuf_ring(ifq);
    kfree(ifq);
}

/*
 * Function: io_register_zcrx_ifq
 * Purpose : Registers a zero‑copy RX interface queue.
 *           Validates parameters from user-space, allocates an interface queue,
 *           sets up the receive buffer ring and area, obtains the network device,
 *           and maps the area for DMA. In case of errors, cleans up allocated resources.
 */
int io_register_zcrx_ifq(struct io_ring_ctx *ctx,
              struct io_uring_zcrx_ifq_reg __user *arg)
{
    struct pp_memory_provider_params mp_param = {};
    struct io_uring_zcrx_area_reg area;
    struct io_uring_zcrx_ifq_reg reg;
    struct io_uring_region_desc rd;
    struct io_zcrx_ifq *ifq;
    int ret;

    /*
     * 1. Interface queue allocation.
     * 2. It can observe data destined for sockets of other tasks.
     */
    if (!capable(CAP_NET_ADMIN))
        return -EPERM;

    /* mandatory io_uring features for zc rx */
    if (!(ctx->flags & IORING_SETUP_DEFER_TASKRUN &&
          ctx->flags & IORING_SETUP_CQE32))
        return -EINVAL;
    if (ctx->ifq)
        return -EBUSY;
    if (copy_from_user(&reg, arg, sizeof(reg)))
        return -EFAULT;
    if (copy_from_user(&rd, u64_to_user_ptr(reg.region_ptr), sizeof(rd)))
        return -EFAULT;
    if (memchr_inv(&reg.__resv, 0, sizeof(reg.__resv)))
        return -EINVAL;
    if (reg.if_rxq == -1 || !reg.rq_entries || reg.flags)
        return -EINVAL;
    if (reg.rq_entries > IO_RQ_MAX_ENTRIES) {
        if (!(ctx->flags & IORING_SETUP_CLAMP))
            return -EINVAL;
        reg.rq_entries = IO_RQ_MAX_ENTRIES;
    }
    reg.rq_entries = roundup_pow_of_two(reg.rq_entries);

    if (copy_from_user(&area, u64_to_user_ptr(reg.area_ptr), sizeof(area)))
        return -EFAULT;

    ifq = io_zcrx_ifq_alloc(ctx);
    if (!ifq)
        return -ENOMEM;

    ret = io_allocate_rbuf_ring(ifq, &reg, &rd);
    if (ret)
        goto err;

    ret = io_zcrx_create_area(ifq, &ifq->area, &area);
    if (ret)
        goto err;

    // Additional setup code follows (not shown in this excerpt)...
    
    // (The rest of the function continues below in the source file.)

    // For brevity, further function body code is not shown here.
    
err:
    io_zcrx_ifq_free(ifq);
    return ret;
}


    /* Set the number of entries in the receive ring from the user-supplied registration */
    ifq->rq_entries = reg.rq_entries;

    /* Obtain the network device by its index; if not found, return -ENODEV */
    ret = -ENODEV;
    ifq->netdev = netdev_get_by_index(current->nsproxy->net_ns, reg.if_idx,
                                       &ifq->netdev_tracker, GFP_KERNEL);
    if (!ifq->netdev)
        goto err;

    /* Get the parent device from the netdev */
    ifq->dev = ifq->netdev->dev.parent;
    ret = -EOPNOTSUPP;
    if (!ifq->dev)
        goto err;
    get_device(ifq->dev);

    /* Map the user buffer area for DMA; if mapping fails, clean up and return an error */
    ret = io_zcrx_map_area(ifq, ifq->area);
    if (ret)
        goto err;

    /* Initialize memory provider parameters and open the RX queue on the network device */
    mp_param.mp_ops = &io_uring_pp_zc_ops;
    mp_param.mp_priv = ifq;
    ret = net_mp_open_rxq(ifq->netdev, reg.if_rxq, &mp_param);
    if (ret)
        goto err;
    ifq->if_rxq = reg.if_rxq;

    /* Fill in the offsets for the receive ring: start of entries, head, and tail */
    reg.offsets.rqes = sizeof(struct io_uring);
    reg.offsets.head = offsetof(struct io_uring, head);
    reg.offsets.tail = offsetof(struct io_uring, tail);

    /* Copy registration results back to user-space */
    if (copy_to_user(arg, &reg, sizeof(reg)) ||
        copy_to_user(u64_to_user_ptr(reg.region_ptr), &rd, sizeof(rd)) ||
        copy_to_user(u64_to_user_ptr(reg.area_ptr), &area, sizeof(area))) {
        ret = -EFAULT;
        goto err;
    }
    /* Registration complete: associate the interface queue with the context */
    ctx->ifq = ifq;
    return 0;
err:
    /* On error, clean up any allocated interface queue resources */
    io_zcrx_ifq_free(ifq);
    return ret;
}

/*
 * Function: io_unregister_zcrx_ifqs
 * Purpose : Unregisters the zero‑copy RX interface queue from the io_uring context.
 *           Assumes the context lock is held, then frees the associated ifq.
 */
void io_unregister_zcrx_ifqs(struct io_ring_ctx *ctx)
{
    struct io_zcrx_ifq *ifq = ctx->ifq;

    lockdep_assert_held(&ctx->uring_lock);

    if (!ifq)
        return;

    ctx->ifq = NULL;
    io_zcrx_ifq_free(ifq);
}

/*
 * Function: __io_zcrx_get_free_niov
 * Purpose : Retrieves a free net_iov descriptor from the area's freelist.
 *           Must be called while holding the freelist lock.
 */
static struct net_iov *__io_zcrx_get_free_niov(struct io_zcrx_area *area)
{
    unsigned niov_idx;

    lockdep_assert_held(&area->freelist_lock);

    niov_idx = area->freelist[--area->free_count];
    return &area->nia.niovs[niov_idx];
}

/*
 * Function: io_zcrx_return_niov_freelist
 * Purpose : Returns a net_iov descriptor back to the area's freelist.
 *           Uses bottom-half locking for safe concurrent access.
 */
static void io_zcrx_return_niov_freelist(struct net_iov *niov)
{
    struct io_zcrx_area *area = io_zcrx_iov_to_area(niov);

    spin_lock_bh(&area->freelist_lock);
    area->freelist[area->free_count++] = net_iov_idx(niov);
    spin_unlock_bh(&area->freelist_lock);
}

/*
 * Function: io_zcrx_return_niov
 * Purpose : Returns a net_iov descriptor to the page pool or freelist.
 *           If the descriptor was allocated via a fallback copy mechanism, it is returned to the freelist.
 */
static void io_zcrx_return_niov(struct net_iov *niov)
{
    netmem_ref netmem = net_iov_to_netmem(niov);

    if (!niov->pp) {
        /* For copy-fallback allocated niovs, simply return to the freelist */
        io_zcrx_return_niov_freelist(niov);
        return;
    }
    /* Release the netmem reference from the page pool */
    page_pool_put_unrefed_netmem(niov->pp, netmem, -1, false);
}

/*
 * Function: io_zcrx_scrub
 * Purpose : Reclaims all buffers that were handed out to user-space but not yet returned.
 *           Iterates through each net_iov descriptor and if user references remain,
 *           clears the counter and returns the buffer.
 */
static void io_zcrx_scrub(struct io_zcrx_ifq *ifq)
{
    struct io_zcrx_area *area = ifq->area;
    int i;

    if (!area)
        return;

    /* Reclaim back all buffers given to user-space */
    for (i = 0; i < area->nia.num_niovs; i++) {
        struct net_iov *niov = &area->nia.niovs[i];
        int nr;

        if (!atomic_read(io_get_user_counter(niov)))
            continue;
        nr = atomic_xchg(io_get_user_counter(niov), 0);
        if (nr && !page_pool_unref_netmem(net_iov_to_netmem(niov), nr))
            io_zcrx_return_niov(niov);
    }
}

/*
 * Function: io_shutdown_zcrx_ifqs
 * Purpose : Shuts down all zero‑copy RX interface queues associated with the context.
 *           Holds the context lock, scrubs any outstanding buffers, and then closes the RX queue.
 */
void io_shutdown_zcrx_ifqs(struct io_ring_ctx *ctx)
{
    lockdep_assert_held(&ctx->uring_lock);

    if (!ctx->ifq)
        return;
    io_zcrx_scrub(ctx->ifq);
    io_close_queue(ctx->ifq);
}

/*
 * Function: io_zcrx_rqring_entries
 * Purpose : Computes the number of available entries in the receive ring.
 *           Calculates the difference between the current tail and cached head
 *           and returns the minimal value up to the total number of entries.
 */
static inline u32 io_zcrx_rqring_entries(struct io_zcrx_ifq *ifq)
{
    u32 entries;

    entries = smp_load_acquire(&ifq->rq_ring->tail) - ifq->cached_rq_head;
    return min(entries, ifq->rq_entries);
}

/*
 * Function: io_zcrx_get_rqe
 * Purpose : Retrieves the next available ring entry from the zero‑copy RX ring.
 *           Uses the cached head index and applies a mask to iterate circularly.
 */
static struct io_uring_zcrx_rqe *io_zcrx_get_rqe(struct io_zcrx_ifq *ifq,
                                                 unsigned mask)
{
    unsigned int idx = ifq->cached_rq_head++ & mask;

    return &ifq->rqes[idx];
}

/*
 * Function: io_zcrx_ring_refill
 * Purpose : Refills the RX ring cache by returning network buffers that have been completed.
 *           Locks the ring, determines how many entries to refill (bounded by the page pool cache limit),
 *           obtains each ring entry, validates and processes the corresponding net_iov,
 *           and then returns the appropriate buffers back to the page pool.
 */
static void io_zcrx_ring_refill(struct page_pool *pp,
                struct io_zcrx_ifq *ifq)
{
    unsigned int mask = ifq->rq_entries - 1;
    unsigned int entries;
    netmem_ref netmem;

    spin_lock_bh(&ifq->rq_lock);

    entries = io_zcrx_rqring_entries(ifq);
    entries = min_t(unsigned, entries, PP_ALLOC_CACHE_REFILL - pp->alloc.count);
    if (unlikely(!entries)) {
        spin_unlock_bh(&ifq->rq_lock);
        return;
    }

    do {
        struct io_uring_zcrx_rqe *rqe = io_zcrx_get_rqe(ifq, mask);
        struct io_zcrx_area *area;
        struct net_iov *niov;
        unsigned niov_idx, area_idx;

        area_idx = rqe->off >> IORING_ZCRX_AREA_SHIFT;
        niov_idx = (rqe->off & ~IORING_ZCRX_AREA_MASK) >> PAGE_SHIFT;

        if (unlikely(rqe->__pad || area_idx))
            continue;
        area = ifq->area;

        if (unlikely(niov_idx >= area->nia.num_niovs))
            continue;
        niov_idx = array_index_nospec(niov_idx, area->nia.num_niovs);

        niov = &area->nia.niovs[niov_idx];
        if (!io_zcrx_put_niov_uref(niov))
            continue;

        netmem = net_iov_to_netmem(niov);
        if (page_pool_unref_netmem(netmem, 1) != 0)
            continue;

        if (unlikely(niov->pp != pp)) {
            io_zcrx_return_niov(niov);
            continue;
        }

        io_zcrx_sync_for_device(pp, niov);
        net_mp_netmem_place_in_cache(pp, netmem);
    } while (--entries);

    smp_store_release(&ifq->rq_ring->head, ifq->cached_rq_head);
    spin_unlock_bh(&ifq->rq_lock);
}

/*
 * Function: io_zcrx_refill_slow
 * Purpose : Performs a slower refill of the buffer cache when the fast path fails.
 *           Locks the area's freelist and returns free net_iov descriptors back to the cache.
 */
static void io_zcrx_refill_slow(struct page_pool *pp, struct io_zcrx_ifq *ifq)
{
    struct io_zcrx_area *area = ifq->area;

    spin_lock_bh(&area->freelist_lock);
    while (area->free_count && pp->alloc.count < PP_ALLOC_CACHE_REFILL) {
        struct net_iov *niov = __io_zcrx_get_free_niov(area);
        netmem_ref netmem = net_iov_to_netmem(niov);

        net_mp_niov_set_page_pool(pp, niov);
        io_zcrx_sync_for_device(pp, niov);
        net_mp_netmem_place_in_cache(pp, netmem);
    }
    spin_unlock_bh(&area->freelist_lock);
}

/*
 * Function: io_pp_zc_alloc_netmems
 * Purpose : Allocates a netmem reference from the page pool cache for zero‑copy operations.
 *           Attempts a fast refill, falls back to a slow refill if necessary,
 *           and then decrements the cache count, returning a netmem reference.
 */
static netmem_ref io_pp_zc_alloc_netmems(struct page_pool *pp, gfp_t gfp)
{
    struct io_zcrx_ifq *ifq = pp->mp_priv;

    /* If there are already allocated netmem references, use one */
    if (unlikely(pp->alloc.count))
        goto out_return;

    io_zcrx_ring_refill(pp, ifq);
    if (likely(pp->alloc.count))
        goto out_return;

    io_zcrx_refill_slow(pp, ifq);
    if (!pp->alloc.count)
        return 0;
out_return:
    return pp->alloc.cache[--pp->alloc.count];
}

/*
 * Function: io_pp_zc_release_netmem
 * Purpose : Releases a netmem reference back to the pool for zero‑copy operations.
 *           Verifies that the netmem reference is of the proper type and returns it to the freelist.
 */
static bool io_pp_zc_release_netmem(struct page_pool *pp, netmem_ref netmem)
{
    struct net_iov *niov;

    if (WARN_ON_ONCE(!netmem_is_net_iov(netmem)))
        return false;

    niov = netmem_to_net_iov(netmem);
    net_mp_niov_clear_page_pool(niov);
    io_zcrx_return_niov_freelist(niov);
    return false;
}

/*
 * Function: io_pp_zc_init
 * Purpose : Initializes the page pool for zero‑copy operations.
 *           Performs several sanity checks and increments a per-CPU reference on the context.
 */
static int io_pp_zc_init(struct page_pool *pp)
{
    struct io_zcrx_ifq *ifq = pp->mp_priv;

    if (WARN_ON_ONCE(!ifq))
        return -EINVAL;
    if (WARN_ON_ONCE(ifq->dev != pp->p.dev))
        return -EINVAL;
    if (WARN_ON_ONCE(!pp->dma_map))
        return -EOPNOTSUPP;
    if (pp->p.order != 0)
        return -EOPNOTSUPP;
    if (pp->p.dma_dir != DMA_FROM_DEVICE)
        return -EOPNOTSUPP;

    percpu_ref_get(&ifq->ctx->refs);
    return 0;
}

/*
 * Function: io_pp_zc_destroy
 * Purpose : Destroys the zero‑copy page pool.
 *           Ensures that all buffers have been returned by checking the free_count,
 *           then decrements the per-CPU reference count on the context.
 */
static void io_pp_zc_destroy(struct page_pool *pp)
{
    struct io_zcrx_ifq *ifq = pp->mp_priv;
    struct io_zcrx_area *area = ifq->area;

    if (WARN_ON_ONCE(area->free_count != area->nia.num_niovs))
        return;
    percpu_ref_put(&ifq->ctx->refs);
}
/*
 * Function: io_pp_nl_fill
 * Purpose : Fill a netlink message with memory provider information.
 *           Creates a nested attribute in the provided sk_buff, returning -EMSGSIZE if the space is insufficient.
 */
static int io_pp_nl_fill(void *mp_priv, struct sk_buff *rsp,
                         struct netdev_rx_queue *rxq)
{
    struct nlattr *nest;
    int type;

    type = rxq ? NETDEV_A_QUEUE_IO_URING : NETDEV_A_PAGE_POOL_IO_URING;
    nest = nla_nest_start(rsp, type);
    if (!nest)
        return -EMSGSIZE;
    nla_nest_end(rsp, nest);

    return 0;
}

/*
 * Function: io_pp_uninstall
 * Purpose : Uninstalls the memory provider for the given netdev RX queue.
 *           Drops the associated network device reference and clears the memory provider operations.
 */
static void io_pp_uninstall(void *mp_priv, struct netdev_rx_queue *rxq)
{
    struct pp_memory_provider_params *p = &rxq->mp_params;
    struct io_zcrx_ifq *ifq = mp_priv;

    io_zcrx_drop_netdev(ifq);
    p->mp_ops = NULL;
    p->mp_priv = NULL;
}

/*
 * Structure: io_uring_pp_zc_ops
 * Purpose   : Defines the memory provider operations for zero‑copy I/O.
 *           This structure is used by the page pool to perform allocation,
 *           release, initialization, destruction, and netlink fill/uninstallation.
 */
static const struct memory_provider_ops io_uring_pp_zc_ops = {
    .alloc_netmems    = io_pp_zc_alloc_netmems,
    .release_netmem   = io_pp_zc_release_netmem,
    .init             = io_pp_zc_init,
    .destroy          = io_pp_zc_destroy,
    .nl_fill          = io_pp_nl_fill,
    .uninstall        = io_pp_uninstall,
};

/*
 * Function: io_zcrx_queue_cqe
 * Purpose : Queues a completion queue entry (CQE) for a zero‑copy RX operation.
 *           It retrieves an uncommitted CQE from the context, sets its user_data, result,
 *           and then writes an extended CQE (zcrx CQE) with the combined offset.
 */
static bool io_zcrx_queue_cqe(struct io_kiocb *req, struct net_iov *niov,
                              struct io_zcrx_ifq *ifq, int off, int len)
{
    struct io_uring_zcrx_cqe *rcqe;
    struct io_zcrx_area *area;
    struct io_uring_cqe *cqe;
    u64 offset;

    if (!io_defer_get_uncommited_cqe(req->ctx, &cqe))
        return false;

    cqe->user_data = req->cqe.user_data;
    cqe->res = len;
    cqe->flags = IORING_CQE_F_MORE;

    area = io_zcrx_iov_to_area(niov);
    offset = off + (net_iov_idx(niov) << PAGE_SHIFT);
    rcqe = (struct io_uring_zcrx_cqe *)(cqe + 1);
    rcqe->off = offset + ((u64)area->area_id << IORING_ZCRX_AREA_SHIFT);
    rcqe->__pad = 0;
    return true;
}

/*
 * Function: io_zcrx_alloc_fallback
 * Purpose : Allocates a fallback net_iov descriptor from the free list in the zcrx area.
 *           Locks the freelist, extracts an available descriptor, and optionally fragments
 *           the corresponding netmem if allocated via fallback.
 */
static struct net_iov *io_zcrx_alloc_fallback(struct io_zcrx_area *area)
{
    struct net_iov *niov = NULL;

    spin_lock_bh(&area->freelist_lock);
    if (area->free_count)
        niov = __io_zcrx_get_free_niov(area);
    spin_unlock_bh(&area->freelist_lock);

    if (niov)
        page_pool_fragment_netmem(net_iov_to_netmem(niov), 1);
    return niov;
}

/*
 * Function: io_zcrx_copy_chunk
 * Purpose : Copies a chunk of data from the source buffer into a new network buffer.
 *           It loops until the requested length is copied or an error occurs.
 *           For each chunk, it allocates a fallback net_iov, maps its page, performs the copy,
 *           queues a CQE, and updates the user reference count.
 */
static ssize_t io_zcrx_copy_chunk(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
                                  void *src_base, struct page *src_page,
                                  unsigned int src_offset, size_t len)
{
    struct io_zcrx_area *area = ifq->area;
    size_t copied = 0;
    int ret = 0;

    while (len) {
        size_t copy_size = min_t(size_t, PAGE_SIZE, len);
        const int dst_off = 0;
        struct net_iov *niov;
        struct page *dst_page;
        void *dst_addr;

        niov = io_zcrx_alloc_fallback(area);
        if (!niov) {
            ret = -ENOMEM;
            break;
        }

        dst_page = io_zcrx_iov_page(niov);
        dst_addr = kmap_local_page(dst_page);
        if (src_page)
            src_base = kmap_local_page(src_page);

        memcpy(dst_addr, src_base + src_offset, copy_size);

        if (src_page)
            kunmap_local(src_base);
        kunmap_local(dst_addr);

        if (!io_zcrx_queue_cqe(req, niov, ifq, dst_off, copy_size)) {
            io_zcrx_return_niov(niov);
            ret = -ENOSPC;
            break;
        }

        io_zcrx_get_niov_uref(niov);
        src_offset += copy_size;
        len -= copy_size;
        copied += copy_size;
    }

    return copied ? copied : ret;
}

/*
 * Function: io_zcrx_copy_frag
 * Purpose : Copies data from a single fragmented buffer (skb fragment) into network buffers.
 *           Iterates over each page within the fragment and uses io_zcrx_copy_chunk to perform the copy.
 */
static int io_zcrx_copy_frag(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
                             const skb_frag_t *frag, int off, int len)
{
    struct page *page = skb_frag_page(frag);
    u32 p_off, p_len, t, copied = 0;
    int ret = 0;

    off += skb_frag_off(frag);

    skb_frag_foreach_page(frag, off, len,
                          page, p_off, p_len, t) {
        ret = io_zcrx_copy_chunk(req, ifq, NULL, page, p_off, p_len);
        if (ret < 0)
            return copied ? copied : ret;
        copied += ret;
    }
    return copied;
}

/*
 * Function: io_zcrx_recv_frag
 * Purpose : Receives a fragmented packet buffer.
 *           If the fragment is not of net_iov type, falls back to copy mode;
 *           otherwise, queues a CQE using the net_iov directly and increments its reference.
 */
static int io_zcrx_recv_frag(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
                             const skb_frag_t *frag, int off, int len)
{
    struct net_iov *niov;

    if (unlikely(!skb_frag_is_net_iov(frag)))
        return io_zcrx_copy_frag(req, ifq, frag, off, len);

    niov = netmem_to_net_iov(frag->netmem);
    if (niov->pp->mp_ops != &io_uring_pp_zc_ops ||
        niov->pp->mp_priv != ifq)
        return -EFAULT;

    if (!io_zcrx_queue_cqe(req, niov, ifq, off + skb_frag_off(frag), len))
        return -ENOSPC;

    /* Increment reference count and mark buffer in use to prevent recycling */
    page_pool_ref_netmem(net_iov_to_netmem(niov));
    io_zcrx_get_niov_uref(niov);
    return len;
}

/*
 * Function: io_zcrx_recv_skb
 * Purpose : Receives data from an sk_buff using zero‑copy mechanisms.
 *           Handles both header and fragmented portions of the SKB by
 *           copying data into buffers using either direct or copy fallback paths.
 *           Returns the number of bytes received or an error code.
 */
static int
io_zcrx_recv_skb(read_descriptor_t *desc, struct sk_buff *skb,
                 unsigned int offset, size_t len)
{
    struct io_zcrx_args *args = desc->arg.data;
    struct io_zcrx_ifq *ifq = args->ifq;
    struct io_kiocb *req = args->req;
    struct sk_buff *frag_iter;
    unsigned start, start_off = offset;
    int i, copy, end, off;
    int ret = 0;

    len = min_t(size_t, len, desc->count);
    /*
     * __tcp_read_sock() calls this even if desc->count is 0.
     * Return early if no bytes need to be processed.
     */
    if (!len)
        return 0;
    if (unlikely(args->nr_skbs++ > IO_SKBS_PER_CALL_LIMIT))
        return -EAGAIN;

    if (unlikely(offset < skb_headlen(skb))) {
        ssize_t copied;
        size_t to_copy;

        to_copy = min_t(size_t, skb_headlen(skb) - offset, len);
        copied = io_zcrx_copy_chunk(req, ifq, skb->data, NULL,
                                    offset, to_copy);
        if (copied < 0) {
            ret = copied;
            goto out;
        }
        offset += copied;
        len -= copied;
        if (!len)
            goto out;
        if (offset != skb_headlen(skb))
            goto out;
    }

    start = skb_headlen(skb);

    for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
        const skb_frag_t *frag;

        if (WARN_ON(start > offset + len))
            return -EFAULT;

        frag = &skb_shinfo(skb)->frags[i];
        end = start + skb_frag_size(frag);

        if (offset < end) {
            copy = end - offset;
            if (copy > len)
                copy = len;

            off = offset - start;
            ret = io_zcrx_recv_frag(req, ifq, frag, off, copy);
            if (ret < 0)
                goto out;

            offset += ret;
            len -= ret;
            if (len == 0 || ret != copy)
                goto out;
        }
        start = end;
    }

    skb_walk_frags(skb, frag_iter) {
        if (WARN_ON(start > offset + len))
            return -EFAULT;

        end = start + frag_iter->len;
        if (offset < end) {
            copy = end - offset;
            if (copy > len)
                copy = len;

            off = offset - start;
            ret = io_zcrx_recv_skb(desc, frag_iter, off, copy);
            if (ret < 0)
                goto out;

            offset += ret;
            len -= ret;
            if (len == 0 || ret != copy)
                goto out;
        }
        start = end;
    }

out:
    if (offset == start_off)
        return ret;
    desc->count -= (offset - start_off);
    return offset - start_off;
}

/*
 * Function: io_zcrx_tcp_recvmsg
 * Purpose : Performs zero‑copy receipt for a TCP socket.
 *           Wraps the tcp_read_sock() call with proper socket locking and
 *           post-processing of the received data, handling errors and re-queueing logic.
 */
static int io_zcrx_tcp_recvmsg(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
                               struct sock *sk, int flags,
                               unsigned issue_flags, unsigned int *outlen)
{
    unsigned int len = *outlen;
    struct io_zcrx_args args = {
        .req = req,
        .ifq = ifq,
        .sock = sk->sk_socket,
    };
    read_descriptor_t rd_desc = {
        .count = len ? len : UINT_MAX,
        .arg.data = &args,
    };
    int ret;

    lock_sock(sk);
    ret = tcp_read_sock(sk, &rd_desc, io_zcrx_recv_skb);
    if (len && ret > 0)
        *outlen = len - ret;
    if (ret <= 0) {
        if (ret < 0 || sock_flag(sk, SOCK_DONE))
            goto out;
        if (sk->sk_err)
            ret = sock_error(sk);
        else if (sk->sk_shutdown & RCV_SHUTDOWN)
            goto out;
        else if (sk->sk_state == TCP_CLOSE)
            ret = -ENOTCONN;
        else
            ret = -EAGAIN;
    } else if (unlikely(args.nr_skbs > IO_SKBS_PER_CALL_LIMIT) &&
               (issue_flags & IO_URING_F_MULTISHOT)) {
        ret = IOU_REQUEUE;
    } else if (sock_flag(sk, SOCK_DONE)) {
        /* Retry until final completion */
        if (issue_flags & IO_URING_F_MULTISHOT)
            ret = IOU_REQUEUE;
        else
            ret = -EAGAIN;
    }
out:
    release_sock(sk);
    return ret;
}

/*
 * Function: io_zcrx_recv
 * Purpose : Entry point for zero‑copy receive operations.
 *           Determines whether the socket supports TCP recvmsg, and if so,
 *           records receive flow information and calls io_zcrx_tcp_recvmsg.
 */
int io_zcrx_recv(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
                 struct socket *sock, unsigned int flags,
                 unsigned issue_flags, unsigned int *len)
{
    struct sock *sk = sock->sk;
    const struct proto *prot = READ_ONCE(sk->sk_prot);

    if (prot->recvmsg != tcp_recvmsg)
        return -EPROTONOSUPPORT;

    sock_rps_record_flow(sk);
    return io_zcrx_tcp_recvmsg(req, ifq, sk, flags, issue_flags, len);
}
