// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_ZC_RX_H
#define IOU_ZC_RX_H

#include <linux/io_uring_types.h>
#include <linux/socket.h>
#include <net/page_pool/types.h>
#include <net/net_trackers.h>

/*
 * Structure: io_zcrx_area
 * Purpose   : Represents the zero‑copy receive buffer area.
 *             It holds the net_iov_area (an array of net_iov descriptors),
 *             a pointer to the associated interface queue, an array of atomic
 *             user reference counters, a flag indicating if the area is mapped,
 *             an area identifier, a pointer to pinned pages, and freelist management data.
 */
struct io_zcrx_area {
    struct net_iov_area nia;
    struct io_zcrx_ifq  *ifq;
    atomic_t        *user_refs;

    bool            is_mapped;
    u16         area_id;
    struct page     **pages;

    /* freelist */
    spinlock_t      freelist_lock ____cacheline_aligned_in_smp;
    u32         free_count;
    u32         *freelist;
};

/*
 * Structure: io_zcrx_ifq
 * Purpose   : Represents the zero‑copy receive interface queue.
 *             It maintains a pointer to the associated io_uring context and zcrx area,
 *             pointers to the receive ring (rq_ring) and its entries (rqes),
 *             the number of ring entries, a cached head index, and a lock to manage access.
 *             Additionally, it stores the RX queue index, a pointer to the network device,
 *             network device tracker, and another lock for miscellaneous operations.
 */
struct io_zcrx_ifq {
    struct io_ring_ctx      *ctx;
    struct io_zcrx_area     *area;

    struct io_uring         *rq_ring;
    struct io_uring_zcrx_rqe    *rqes;
    u32             rq_entries;
    u32             cached_rq_head;
    spinlock_t          rq_lock;

    u32             if_rxq;
    struct device           *dev;
    struct net_device       *netdev;
    netdevice_tracker       netdev_tracker;
    spinlock_t          lock;
};

#if defined(CONFIG_IO_URING_ZCRX)

/*
 * Function: io_register_zcrx_ifq
 * Purpose : Registers a zero‑copy RX interface queue with the given io_uring context.
 *           Sets up the data structures required for zero‑copy receive operations based on user‐provided parameters.
 */
int io_register_zcrx_ifq(struct io_ring_ctx *ctx,
             struct io_uring_zcrx_ifq_reg __user *arg);

/*
 * Function: io_unregister_zcrx_ifqs
 * Purpose : Unregisters and releases all zero‑copy RX interface queues associated with the io_uring context.
 */
void io_unregister_zcrx_ifqs(struct io_ring_ctx *ctx);

/*
 * Function: io_shutdown_zcrx_ifqs
 * Purpose : Shuts down the zero‑copy RX interface queues by cleaning up pending buffers
 *           and closing the receive queues.
 */
void io_shutdown_zcrx_ifqs(struct io_ring_ctx *ctx);

/*
 * Function: io_zcrx_recv
 * Purpose : Performs a zero‑copy receive operation using the zero‑copy RX interface queue.
 *           Receives data from a socket and fills the provided output length.
 */
int io_zcrx_recv(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
         struct socket *sock, unsigned int flags,
         unsigned issue_flags, unsigned int *len);
#else
static inline int io_register_zcrx_ifq(struct io_ring_ctx *ctx,
                    struct io_uring_zcrx_ifq_reg __user *arg)
{
    return -EOPNOTSUPP;
}
static inline void io_unregister_zcrx_ifqs(struct io_ring_ctx *ctx)
{
}
static inline void io_shutdown_zcrx_ifqs(struct io_ring_ctx *ctx)
{
}
static inline int io_zcrx_recv(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
                   struct socket *sock, unsigned int flags,
                   unsigned issue_flags, unsigned int *len)
{
    return -EOPNOTSUPP;
}
#endif

/*
 * Function: io_recvzc
 * Purpose : Executes a zero‑copy receive operation.
 *           This higher-level function is used to initiate zero‑copy receives.
 */
int io_recvzc(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Function: io_recvzc_prep
 * Purpose : Prepares a zero‑copy receive request.
 *           Extracts and validates parameters from the SQE for zero‑copy receive operations.
 */
int io_recvzc_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

#endif
