// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/io_uring.h>

#include <trace/events/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "refs.h"
#include "cancel.h"
#include "timeout.h"

/*
 * Structure: io_timeout
 * Purpose   : Holds timeout parameters for an I/O request.
 *             Fields include:
 *               - file: associated file pointer.
 *               - off: deadline offset (or sequence) for the timeout.
 *               - target_seq: the target sequence number after which the timeout expires.
 *               - repeats: for repeated (multishot) timeouts.
 *               - list: linked list field for timeouts.
 *               - head: for linked timeouts, points to the head request.
 *               - prev: previous request in a linked chain.
 */
struct io_timeout {
    struct file         *file;
    u32             off;
    u32             target_seq;
    u32             repeats;
    struct list_head        list;
    /* head of the link, used by linked timeouts only */
    struct io_kiocb         *head;
    /* for linked completions */
    struct io_kiocb         *prev;
};

/*
 * Structure: io_timeout_rem
 * Purpose   : Holds timeout update information.
 *             Contains a file pointer, a user-space address for update,
 *             a timestamp, flags, and a boolean indicating local timeout.
 */
struct io_timeout_rem {
    struct file         *file;
    u64             addr;
    /* timeout update */
    struct timespec64       ts;
    u32             flags;
    bool                ltimeout;
};

/*
 * Function: io_is_timeout_noseq
 * Purpose : Determines whether a timeout request has no sequence or is a multishot.
 *           Checks whether the timeout offset is zero or if the multishot flag is set.
 */
static inline bool io_is_timeout_noseq(struct io_kiocb *req)
{
    struct io_timeout *timeout = io_kiocb_to_cmd(req, struct io_timeout);
    struct io_timeout_data *data = req->async_data;

    return !timeout->off || data->flags & IORING_TIMEOUT_MULTISHOT;
}

/*
 * Function: io_put_req
 * Purpose : Drops a reference to the I/O request; if the reference count reaches zero,
 *           queues the next request and frees the request structure.
 */
static inline void io_put_req(struct io_kiocb *req)
{
    if (req_ref_put_and_test(req)) {
        io_queue_next(req);
        io_free_req(req);
    }
}

/*
 * Function: io_timeout_finish
 * Purpose : Determines if the timeout should be finished.
 *           For multishot timeouts, checks if:
 *             - no offset is set, or
 *             - if repeats remain (and decrements repeats) → returns false if more repeats needed;
 *           otherwise, returns true meaning the timeout is complete.
 */
static inline bool io_timeout_finish(struct io_timeout *timeout,
                     struct io_timeout_data *data)
{
    if (!(data->flags & IORING_TIMEOUT_MULTISHOT))
        return true;

    if (!timeout->off || (timeout->repeats && --timeout->repeats))
        return false;

    return true;
}

/* Forward declaration for the hrtimer callback */
static enum hrtimer_restart io_timeout_fn(struct hrtimer *timer);

/*
 * Function: io_timeout_complete
 * Purpose : Completes a timeout request.
 *           Checks if the timeout should be repeated (multishot). If so, attempts to re-arm
 *           the timer (and post a completion with IORING_CQE_F_MORE). If not, completes the task work.
 */
static void io_timeout_complete(struct io_kiocb *req, io_tw_token_t tw)
{
    struct io_timeout *timeout = io_kiocb_to_cmd(req, struct io_timeout);
    struct io_timeout_data *data = req->async_data;
    struct io_ring_ctx *ctx = req->ctx;

    if (!io_timeout_finish(timeout, data)) {
        if (io_req_post_cqe(req, -ETIME, IORING_CQE_F_MORE)) {
            /* Re-arm the timer: add the timeout back and restart the hrtimer */
            raw_spin_lock_irq(&ctx->timeout_lock);
            list_add(&timeout->list, ctx->timeout_list.prev);
            hrtimer_start(&data->timer, timespec64_to_ktime(data->ts), data->mode);
            raw_spin_unlock_irq(&ctx->timeout_lock);
            return;
        }
    }

    io_req_task_complete(req, tw);
}

/*
 * Function: io_flush_killed_timeouts
 * Purpose : Flushes any timeouts that have been marked for removal.
 *           If the provided list of timeouts is non-empty, iterates over it,
 *           failing each request and completing its task work.
 *           Returns true if any timeouts were flushed.
 */
static __cold bool io_flush_killed_timeouts(struct list_head *list, int err)
{
    if (list_empty(list))
        return false;

    while (!list_empty(list)) {
        struct io_timeout *timeout;
        struct io_kiocb *req;

        timeout = list_first_entry(list, struct io_timeout, list);
        list_del_init(&timeout->list);
        req = cmd_to_io_kiocb(timeout);
        if (err)
            req_set_fail(req);
        io_req_queue_tw_complete(req, err);
    }

    return true;
}

/*
 * Function: io_kill_timeout
 * Purpose : Cancels a timeout request.
 *           Attempts to cancel the associated hrtimer. If successful, increments the CQ timeout counter
 *           and moves the timeout to the provided list.
 *           Must be called with the ctx->timeout_lock held.
 */
static void io_kill_timeout(struct io_kiocb *req, struct list_head *list)
    __must_hold(&req->ctx->timeout_lock)
{
    struct io_timeout_data *io = req->async_data;

    if (hrtimer_try_to_cancel(&io->timer) != -1) {
        struct io_timeout *timeout = io_kiocb_to_cmd(req, struct io_timeout);

        atomic_set(&req->ctx->cq_timeouts,
            atomic_read(&req->ctx->cq_timeouts) + 1);
        list_move_tail(&timeout->list, list);
    }
}

/*
 * Function: io_flush_timeouts
 * Purpose : Flushes completed timeouts for the given io_uring context.
 *           Determines the current event sequence, and for each timeout in the context's list,
 *           checks if its target sequence has been reached. If so, marks the timeout to be killed,
 *           and then flushes all such killed timeouts.
 */
__cold void io_flush_timeouts(struct io_ring_ctx *ctx)
{
    struct io_timeout *timeout, *tmp;
    LIST_HEAD(list);
    u32 seq;

    raw_spin_lock_irq(&ctx->timeout_lock);
    seq = ctx->cached_cq_tail - atomic_read(&ctx->cq_timeouts);

    list_for_each_entry_safe(timeout, tmp, &ctx->timeout_list, list) {
        struct io_kiocb *req = cmd_to_io_kiocb(timeout);
        u32 events_needed, events_got;

        if (io_is_timeout_noseq(req))
            break;

        /*
         * Adjust for potential wraparound by subtracting the last flush sequence.
         * This allows us to check if the target sequence is within the flushed range.
         */
        events_needed = timeout->target_seq - ctx->cq_last_tm_flush;
        events_got = seq - ctx->cq_last_tm_flush;
        if (events_got < events_needed)
            break;

        io_kill_timeout(req, &list);
    }
    ctx->cq_last_tm_flush = seq;
    raw_spin_unlock_irq(&ctx->timeout_lock);
    io_flush_killed_timeouts(&list, 0);
}

/*
 * Function: io_req_tw_fail_links
 * Purpose : Fails a chain of linked requests.
 *           For each request in the chain, if it has already already failed, uses its result;
 *           Otherwise, sets the result to -ECANCELED, completes task work, and then moves to the next link.
 */
static void io_req_tw_fail_links(struct io_kiocb *link, io_tw_token_t tw)
{
    io_tw_lock(link->ctx, tw);
    while (link) {
        struct io_kiocb *nxt = link->link;
        long res = -ECANCELED;

        if (link->flags & REQ_F_FAIL)
            res = link->cqe.res;
        link->link = NULL;
        io_req_set_res(link, res, 0);
        io_req_task_complete(link, tw);
        link = nxt;
    }
}

/*
 * Function: io_fail_links
 * Purpose : Fails all linked requests for a given request.
 *           Iterates through all links of the main request, marks the CQE skip flag if needed,
 *           and then schedules the failure function via task work.
 *           Must be called with the ctx->completion_lock held.
 */
static void io_fail_links(struct io_kiocb *req)
    __must_hold(&req->ctx->completion_lock)
{
    struct io_kiocb *link = req->link;
    bool ignore_cqes = req->flags & REQ_F_SKIP_LINK_CQES;

    if (!link)
        return;

    while (link) {
        if (ignore_cqes)
            link->flags |= REQ_F_CQE_SKIP;
        else
            link->flags &= ~REQ_F_CQE_SKIP;
        trace_io_uring_fail_link(req, link);
        link = link->link;
    }

    link = req->link;
    link->io_task_work.func = io_req_tw_fail_links;
    io_req_task_work_add(link);
    req->link = NULL;
}

/*
 * Function: io_remove_next_linked
 * Purpose : Removes the next linked request from the linked chain.
 *           Updates the main request's link pointer and clears the removed node's link pointer.
 */
static inline void io_remove_next_linked(struct io_kiocb *req)
{
    struct io_kiocb *nxt = req->link;

    req->link = nxt->link;
    nxt->link = NULL;
}

/*
 * Function: io_disarm_next
 * Purpose : Disarms the timeout linked to this request.
 *           Based on various flags (ARM_LTIMEOUT or LINK_TIMEOUT), it clears the timeout,
 *           cancels the associated timer if needed, and, if the request has failed and isn't hardlinked,
 *           calls io_fail_links() to fail the chain.
 *           Must be called with the ctx->completion_lock held.
 */
void io_disarm_next(struct io_kiocb *req)
    __must_hold(&req->ctx->completion_lock)
{
    struct io_kiocb *link = NULL;

    if (req->flags & REQ_F_ARM_LTIMEOUT) {
        link = req->link;
        req->flags &= ~REQ_F_ARM_LTIMEOUT;
        if (link && link->opcode == IORING_OP_LINK_TIMEOUT) {
            io_remove_next_linked(req);
            io_req_queue_tw_complete(link, -ECANCELED);
        }
    } else if (req->flags & REQ_F_LINK_TIMEOUT) {
        struct io_ring_ctx *ctx = req->ctx;

        raw_spin_lock_irq(&ctx->timeout_lock);
        link = io_disarm_linked_timeout(req);
        raw_spin_unlock_irq(&ctx->timeout_lock);
        if (link)
            io_req_queue_tw_complete(link, -ECANCELED);
    }
    if (unlikely((req->flags & REQ_F_FAIL) &&
             !(req->flags & REQ_F_HARDLINK)))
        io_fail_links(req);
}

/*
 * Function: __io_disarm_linked_timeout
 * Purpose : Helper to disarm a linked timeout.
 *           Removes a linked timeout from the chain, sets its head pointer to NULL,
 *           cancels its hrtimer, and returns the linked request if successful.
 *           Must be called with both the completion_lock and timeout_lock held.
 */
struct io_kiocb *__io_disarm_linked_timeout(struct io_kiocb *req,
                        struct io_kiocb *link)
    __must_hold(&req->ctx->completion_lock)
    __must_hold(&req->ctx->timeout_lock)
{
    struct io_timeout_data *io = link->async_data;
    struct io_timeout *timeout = io_kiocb_to_cmd(link, struct io_timeout);

    io_remove_next_linked(req);
    timeout->head = NULL;
    if (hrtimer_try_to_cancel(&io->timer) != -1) {
        list_del(&timeout->list);
        return link;
    }

    return NULL;
}

/*
 * Function: io_timeout_fn
 * Purpose : The hrtimer callback for timeouts.
 *           When the timer fires, it removes the timeout from the list, increments the CQ timeouts counter,
 *           fails the request if the ETIME success flag is not set,
 *           sets the request result to -ETIME, enqueues the timeout complete task work,
 *           and returns HRTIMER_NORESTART.
 */
static enum hrtimer_restart io_timeout_fn(struct hrtimer *timer)
{
    struct io_timeout_data *data = container_of(timer,
                        struct io_timeout_data, timer);
    struct io_kiocb *req = data->req;
    struct io_timeout *timeout = io_kiocb_to_cmd(req, struct io_timeout);
    struct io_ring_ctx *ctx = req->ctx;
    unsigned long flags;

    raw_spin_lock_irqsave(&ctx->timeout_lock, flags);
    list_del_init(&timeout->list);
    atomic_set(&req->ctx->cq_timeouts,
        atomic_read(&req->ctx->cq_timeouts) + 1);
    raw_spin_unlock_irqrestore(&ctx->timeout_lock, flags);

    if (!(data->flags & IORING_TIMEOUT_ETIME_SUCCESS))
        req_set_fail(req);

    io_req_set_res(req, -ETIME, 0);
    req->io_task_work.func = io_timeout_complete;
    io_req_task_work_add(req);
    return HRTIMER_NORESTART;
}

/*
 * Function: io_timeout_extract
 * Purpose : Extracts a timeout request matching the cancel data from the context's timeout list.
 *           Iterates over the timeout list, and if a matching request is found,
 *           tries to cancel its hrtimer. If successful, removes the timeout from the list.
 *           Must be called with the ctx->timeout_lock held.
 */
static struct io_kiocb *io_timeout_extract(struct io_ring_ctx *ctx,
                       struct io_cancel_data *cd)
    __must_hold(&ctx->timeout_lock)
{
    struct io_timeout *timeout;
    struct io_timeout_data *io;
    struct io_kiocb *req = NULL;

    list_for_each_entry(timeout, &ctx->timeout_list, list) {
        struct io_kiocb *tmp = cmd_to_io_kiocb(timeout);
        if (io_cancel_req_match(tmp, cd)) {
            req = tmp;
            break;
        }
    }
    if (!req)
        return ERR_PTR(-ENOENT);

    io = req->async_data;
    if (hrtimer_try_to_cancel(&io->timer) == -1)
        return ERR_PTR(-EALREADY);
    timeout = io_kiocb_to_cmd(req, struct io_timeout);
    list_del_init(&timeout->list);
    return req;
}

/*
 * Function: io_timeout_cancel
 * Purpose : Cancels a timeout request matching the provided cancel data.
 *           With the ctx->completion_lock held, it extracts the matching timeout,
 *           and then queues a failure with -ECANCELED for that request.
 */
int io_timeout_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd)
    __must_hold(&ctx->completion_lock)
{
    struct io_kiocb *req;

    raw_spin_lock_irq(&ctx->timeout_lock);
    req = io_timeout_extract(ctx, cd);
    raw_spin_unlock_irq(&ctx->timeout_lock);

    if (IS_ERR(req))
        return PTR_ERR(req);
    io_req_task_queue_fail(req, -ECANCELED);
    return 0;
}

/*
 * Function: io_req_task_link_timeout
 * Purpose : Processes a linked timeout for a request.
 *           If the request has a previous linked request, tries to cancel it.
 *           Sets the result of the current request accordingly, completes its task work,
 *           and releases the previous request.
 */
static void io_req_task_link_timeout(struct io_kiocb *req, io_tw_token_t tw)
{
    struct io_timeout *timeout = io_kiocb_to_cmd(req, struct io_timeout);
    struct io_kiocb *prev = timeout->prev;
    int ret;

    if (prev) {
        if (!io_should_terminate_tw()) {
            struct io_cancel_data cd = {
                .ctx        = req->ctx,
                .data       = prev->cqe.user_data,
            };
            ret = io_try_cancel(req->tctx, &cd, 0);
        } else {
            ret = -ECANCELED;
        }
        io_req_set_res(req, ret ?: -ETIME, 0);
        io_req_task_complete(req, tw);
        io_put_req(prev);
    } else {
        io_req_set_res(req, -ETIME, 0);
        io_req_task_complete(req, tw);
    }
}

/*
 * Function: io_link_timeout_fn
 * Purpose : The hrtimer callback for a linked timeout.
 *           When a linked timeout fires, it disarms the timeout from the chain,
 *           tries to increment a reference on the previous request, and then schedules
 *           the linked timeout failure task work.
 */
static enum hrtimer_restart io_link_timeout_fn(struct hrtimer *timer)
{
    struct io_timeout_data *data = container_of(timer,
                        struct io_timeout_data, timer);
    struct io_kiocb *prev, *req = data->req;
    struct io_timeout *timeout = io_kiocb_to_cmd(req, struct io_timeout);
    struct io_ring_ctx *ctx = req->ctx;
    unsigned long flags;

    raw_spin_lock_irqsave(&ctx->timeout_lock, flags);
    prev = timeout->head;
    timeout->head = NULL;

    /*
     * If the linked timeout list is not empty, remove the next linked request.
     * If we cannot increase the reference on the previous request, set it to NULL.
     */
    if (prev) {
        io_remove_next_linked(prev);
        if (!req_ref_inc_not_zero(prev))
            prev = NULL;
    }
    list_del(&timeout->list);
    timeout->prev = prev;
    raw_spin_unlock_irqrestore(&ctx->timeout_lock, flags);

    req->io_task_work.func = io_req_task_link_timeout;
    io_req_task_work_add(req);
    return HRTIMER_NORESTART;
}


/* 
 * Determine the clock to use for a timeout based on the timeout flags.
 * It supports BOOTTIME, REALTIME, and defaults to MONOTONIC. The default 
 * case should never occur because the flags are validated at preparation.
 */
static clockid_t io_timeout_get_clock(struct io_timeout_data *data)
{
    switch (data->flags & IORING_TIMEOUT_CLOCK_MASK) {
    case IORING_TIMEOUT_BOOTTIME:
        return CLOCK_BOOTTIME;
    case IORING_TIMEOUT_REALTIME:
        return CLOCK_REALTIME;
    default:
        /* Should never happen – flags are vetted during prep */
        WARN_ON_ONCE(1);
        fallthrough;
    case 0:
        return CLOCK_MONOTONIC;
    }
}

/*
 * Update an existing linked timeout.
 * - Searches the linked timeout list (ctx->ltimeout_list) for a timeout 
 *   whose user data matches the provided user_data.
 * - If found, attempts to cancel its timer. If cancellation succeeds, 
 *   it reinitializes the timer using the new timestamp (ts) and hrtimer mode,
 *   and starts the timer.
 * - Returns 0 on success, or an error if no matching timeout is found (-ENOENT)
 *   or if the timer could not be cancelled (-EALREADY).
 *
 * Note: This function must be called with ctx->timeout_lock held.
 */
static int io_linked_timeout_update(struct io_ring_ctx *ctx, __u64 user_data,
                    struct timespec64 *ts, enum hrtimer_mode mode)
    __must_hold(&ctx->timeout_lock)
{
    struct io_timeout_data *io;
    struct io_timeout *timeout;
    struct io_kiocb *req = NULL;

    /* Search the linked timeout list for a matching timeout */
    list_for_each_entry(timeout, &ctx->ltimeout_list, list) {
        struct io_kiocb *tmp = cmd_to_io_kiocb(timeout);
        if (user_data == tmp->cqe.user_data) {
            req = tmp;
            break;
        }
    }
    if (!req)
        return -ENOENT;  /* No matching timeout found */

    io = req->async_data;
    /* If the timer cannot be cancelled, return -EALREADY */
    if (hrtimer_try_to_cancel(&io->timer) == -1)
        return -EALREADY;
    /* Reinitialize the hrtimer with the new settings */
    hrtimer_setup(&io->timer, io_link_timeout_fn, io_timeout_get_clock(io), mode);
    /* Start the hrtimer with the new target timestamp */
    hrtimer_start(&io->timer, timespec64_to_ktime(*ts), mode);
    return 0;
}

/*
 * Updates a non-linked timeout.
 * - Uses io_timeout_extract() to find the timeout request that matches the provided user_data.
 * - Sets the timeout's off field to 0 to indicate no sequence is used.
 * - Updates the timestamp in the timeout data.
 * - Adds the timeout to the context's timeout_list.
 * - Sets up and starts the hrtimer with the updated timestamp and mode.
 *
 * Note: Must be called with ctx->timeout_lock held.
 */
static int io_timeout_update(struct io_ring_ctx *ctx, __u64 user_data,
                 struct timespec64 *ts, enum hrtimer_mode mode)
    __must_hold(&ctx->timeout_lock)
{
    struct io_cancel_data cd = { .ctx = ctx, .data = user_data, };
    struct io_kiocb *req = io_timeout_extract(ctx, &cd);
    struct io_timeout *timeout = io_kiocb_to_cmd(req, struct io_timeout);
    struct io_timeout_data *data;

    if (IS_ERR(req))
        return PTR_ERR(req);

    timeout->off = 0; /* no sequence timeout */
    data = req->async_data;
    data->ts = *ts;

    /* Add the timeout to the tail of the context's timeout list */
    list_add_tail(&timeout->list, &ctx->timeout_list);
    /* Reinitialize and start the hrtimer */
    hrtimer_setup(&data->timer, io_timeout_fn, io_timeout_get_clock(data), mode);
    hrtimer_start(&data->timer, timespec64_to_ktime(data->ts), mode);
    return 0;
}

/*
 * Prepares a timeout removal/update request.
 * - Reads various timeout parameters from the SQE.
 * - Validates that no unsupported fields (buf_index, len, splice_fd_in) are set.
 * - Reads the timeout update flags and, if set, validates:
 *      * That at most one clock type is specified.
 *      * If IORING_LINK_TIMEOUT_UPDATE is set, marks tr->ltimeout as true.
 *      * That no flags beyond those allowed for updating are set.
 *      * That the user-supplied timespec (from addr2) is valid (non-negative).
 * - For removal requests, no flags are allowed.
 *
 * Returns 0 on success or an appropriate negative error code.
 */
int io_timeout_remove_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
    struct io_timeout_rem *tr = io_kiocb_to_cmd(req, struct io_timeout_rem);

    if (unlikely(req->flags & (REQ_F_FIXED_FILE | REQ_F_BUFFER_SELECT)))
        return -EINVAL;
    if (sqe->buf_index || sqe->len || sqe->splice_fd_in)
        return -EINVAL;

    tr->ltimeout = false;
    tr->addr = READ_ONCE(sqe->addr);
    tr->flags = READ_ONCE(sqe->timeout_flags);
    if (tr->flags & IORING_TIMEOUT_UPDATE_MASK) {
        if (hweight32(tr->flags & IORING_TIMEOUT_CLOCK_MASK) > 1)
            return -EINVAL;
        if (tr->flags & IORING_LINK_TIMEOUT_UPDATE)
            tr->ltimeout = true;
        if (tr->flags & ~(IORING_TIMEOUT_UPDATE_MASK|IORING_TIMEOUT_ABS))
            return -EINVAL;
        if (get_timespec64(&tr->ts, u64_to_user_ptr(sqe->addr2)))
            return -EFAULT;
        if (tr->ts.tv_sec < 0 || tr->ts.tv_nsec < 0)
            return -EINVAL;
    } else if (tr->flags) {
        /* If any flags are present without the update mask, that's invalid */
        return -EINVAL;
    }

    return 0;
}

/*
 * Translates the timeout flags into an hrtimer_mode.
 * Returns HRTIMER_MODE_ABS if the ABS flag is set, otherwise HRTIMER_MODE_REL.
 */
static inline enum hrtimer_mode io_translate_timeout_mode(unsigned int flags)
{
    return (flags & IORING_TIMEOUT_ABS) ? HRTIMER_MODE_ABS
                        : HRTIMER_MODE_REL;
}

/*
 * Remove or update an existing timeout command.
 * - If the timeout update flag is not set in the removal request,
 *   it cancels the timeout using io_timeout_cancel().
 * - Otherwise, it determines the hrtimer_mode from the flags, and either
 *   calls io_linked_timeout_update (if it's a linked timeout) or io_timeout_update.
 * - Finally, sets the result of the request and returns IOU_OK.
 */
int io_timeout_remove(struct io_kiocb *req, unsigned int issue_flags)
{
    struct io_timeout_rem *tr = io_kiocb_to_cmd(req, struct io_timeout_rem);
    struct io_ring_ctx *ctx = req->ctx;
    int ret;

    if (!(tr->flags & IORING_TIMEOUT_UPDATE)) {
        struct io_cancel_data cd = { .ctx = ctx, .data = tr->addr, };

        spin_lock(&ctx->completion_lock);
        ret = io_timeout_cancel(ctx, &cd);
        spin_unlock(&ctx->completion_lock);
    } else {
        enum hrtimer_mode mode = io_translate_timeout_mode(tr->flags);

        raw_spin_lock_irq(&ctx->timeout_lock);
        if (tr->ltimeout)
            ret = io_linked_timeout_update(ctx, tr->addr, &tr->ts, mode);
        else
            ret = io_timeout_update(ctx, tr->addr, &tr->ts, mode);
        raw_spin_unlock_irq(&ctx->timeout_lock);
    }

    if (ret < 0)
        req_set_fail(req);
    io_req_set_res(req, ret, 0);
    return IOU_OK;
}

/*
 * Internal helper to prepare a timeout request.
 * - Validates the SQE: must have exactly len==1 and no unexpected fields.
 * - For linked timeouts (is_timeout_link true), off must be zero.
 * - Reads the timeout flags, ensuring only supported flags are set.
 * - Initializes the timeout structure's list and sets its off field.
 * - If multishot is enabled and off > 0, stores off in repeats for count tracking.
 * - Allocates the async data for the request, initializes it (including reading the target timestamp),
 *   and sets the hrtimer according to whether this is a linked timeout or a normal timeout.
 */
static int __io_timeout_prep(struct io_kiocb *req,
                 const struct io_uring_sqe *sqe,
                 bool is_timeout_link)
{
    struct io_timeout *timeout = io_kiocb_to_cmd(req, struct io_timeout);
    struct io_timeout_data *data;
    unsigned flags;
    u32 off = READ_ONCE(sqe->off);

    /* Validate unexpected SQE fields */
    if (sqe->buf_index || sqe->len != 1 || sqe->splice_fd_in)
        return -EINVAL;
    /* For linked timeouts, off must be zero */
    if (off && is_timeout_link)
        return -EINVAL;
    flags = READ_ONCE(sqe->timeout_flags);
    if (flags & ~(IORING_TIMEOUT_ABS | IORING_TIMEOUT_CLOCK_MASK |
              IORING_TIMEOUT_ETIME_SUCCESS |
              IORING_TIMEOUT_MULTISHOT))
        return -EINVAL;
    /* Only one clock flag is allowed */
    if (hweight32(flags & IORING_TIMEOUT_CLOCK_MASK) > 1)
        return -EINVAL;
    /* Multishot requests only make sense with relative values */
    if (!(~flags & (IORING_TIMEOUT_MULTISHOT | IORING_TIMEOUT_ABS)))
        return -EINVAL;

    /* Initialize the timeout list field */
    INIT_LIST_HEAD(&timeout->list);
    timeout->off = off;
    if (unlikely(off && !req->ctx->off_timeout_used))
        req->ctx->off_timeout_used = true;
    /* For multishot requests with a fixed number of repeats, store the count */
    timeout->repeats = 0;
    if ((flags & IORING_TIMEOUT_MULTISHOT) && off > 0)
        timeout->repeats = off;

    if (WARN_ON_ONCE(req_has_async_data(req)))
        return -EFAULT;
    data = io_uring_alloc_async_data(NULL, req);
    if (!data)
        return -ENOMEM;
    data->req = req;
    data->flags = flags;

    /* Read the target timestamp from user space */
    if (get_timespec64(&data->ts, u64_to_user_ptr(sqe->addr)))
        return -EFAULT;

    if (data->ts.tv_sec < 0 || data->ts.tv_nsec < 0)
        return -EINVAL;

    data->mode = io_translate_timeout_mode(flags);

    if (is_timeout_link) {
        struct io_submit_link *link = &req->ctx->submit_state.link;

        if (!link->head)
            return -EINVAL;
        if (link->last->opcode == IORING_OP_LINK_TIMEOUT)
            return -EINVAL;
        timeout->head = link->last;
        link->last->flags |= REQ_F_ARM_LTIMEOUT;
        /* Setup the hrtimer for a linked timeout */
        hrtimer_setup(&data->timer, io_link_timeout_fn, io_timeout_get_clock(data),
                  data->mode);
    } else {
        /* Setup the hrtimer for a normal timeout */
        hrtimer_setup(&data->timer, io_timeout_fn, io_timeout_get_clock(data), data->mode);
    }
    return 0;
}

/*
 * Public entry points for preparing timeout requests.
 */
int io_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
    return __io_timeout_prep(req, sqe, false);
}

int io_link_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
    return __io_timeout_prep(req, sqe, true);
}

/*
 * Executes a timeout request.
 * - Computes the target sequence for a sequence-based timeout, if applicable.
 * - Otherwise, for pure timeouts (no sequence), it uses the last element in the timeout list.
 * - Starts the hrtimer with the target timestamp.
 */
int io_timeout(struct io_kiocb *req, unsigned int issue_flags)
{
    struct io_timeout *timeout = io_kiocb_to_cmd(req, struct io_timeout);
    struct io_ring_ctx *ctx = req->ctx;
    struct io_timeout_data *data = req->async_data;
    struct list_head *entry;
    u32 tail, off = timeout->off;

    raw_spin_lock_irq(&ctx->timeout_lock);

    /*
     * For pure timeouts (no sequence), use the tail of the timeout list.
     */
    if (io_is_timeout_noseq(req)) {
        entry = ctx->timeout_list.prev;
        goto add;
    }

    /* Calculate current sequence: current SQ CQ tail minus already processed timeouts */
    tail = data_race(ctx->cached_cq_tail) - atomic_read(&ctx->cq_timeouts);
    timeout->target_seq = tail + off;

    /* Update the last flushed sequence, since completions and submissions don't mix here */
    ctx->cq_last_tm_flush = tail;

    /*
     * Insertion-sort the timeout in the timeout list so that the earliest-expiring timeout is processed first.
     */
    list_for_each_prev(entry, &ctx->timeout_list) {
        struct io_timeout *nextt = list_entry(entry, struct io_timeout, list);
        struct io_kiocb *nxt = cmd_to_io_kiocb(nextt);
        if (io_is_timeout_noseq(nxt))
            continue;
        if (off >= nextt->target_seq - tail)
            break;
    }
add:
    list_add(&timeout->list, entry);
    hrtimer_start(&data->timer, timespec64_to_ktime(data->ts), data->mode);
    raw_spin_unlock_irq(&ctx->timeout_lock);
    return IOU_ISSUE_SKIP_COMPLETE;
}

/*
 * Queues a linked timeout.
 * - If the linked timeout's back reference is still valid, restarts its timer and moves it
 *   to the context's linked timeout list.
 * - After queuing the linked timeout, releases the submission reference.
 */
void io_queue_linked_timeout(struct io_kiocb *req)
{
    struct io_timeout *timeout = io_kiocb_to_cmd(req, struct io_timeout);
    struct io_ring_ctx *ctx = req->ctx;

    raw_spin_lock_irq(&ctx->timeout_lock);
    if (timeout->head) {  /* Check that the linked reference is still valid */
        struct io_timeout_data *data = req->async_data;
        hrtimer_start(&data->timer, timespec64_to_ktime(data->ts), data->mode);
        list_add_tail(&timeout->list, &ctx->ltimeout_list);
    }
    raw_spin_unlock_irq(&ctx->timeout_lock);
    /* Drop the submission reference for this timeout request */
    io_put_req(req);
}

/*
 * Checks whether the tasks linked to a timeout request match a given io_uring task
 * (or if cancel_all is true, matches any task).
 * Must be called with the context's timeout_lock held.
 */
static bool io_match_task(struct io_kiocb *head, struct io_uring_task *tctx,
              bool cancel_all)
    __must_hold(&head->ctx->timeout_lock)
{
    struct io_kiocb *req;
    if (tctx && head->tctx != tctx)
        return false;
    if (cancel_all)
        return true;

    io_for_each_link(req, head) {
        if (req->flags & REQ_F_INFLIGHT)
            return true;
    }
    return false;
}

/*
 * Searches for and kills any pending timeouts that match a given task criteria.
 * - Iterates over the timeout list to find requests matching the criteria provided
 *   by io_match_task() and cancels them via io_kill_timeout().
 * - Returns true if one or more timeouts were killed.
 */
__cold bool io_kill_timeouts(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
                 bool cancel_all)
{
    struct io_timeout *timeout, *tmp;
    LIST_HEAD(list);

    /* Acquire completion_lock then timeout_lock in order for proper lock ordering */
    spin_lock(&ctx->completion_lock);
    raw_spin_lock_irq(&ctx->timeout_lock);
    list_for_each_entry_safe(timeout, tmp, &ctx->timeout_list, list) {
        struct io_kiocb *req = cmd_to_io_kiocb(timeout);
        if (io_match_task(req, tctx, cancel_all))
            io_kill_timeout(req, &list);
    }
    raw_spin_unlock_irq(&ctx->timeout_lock);
    spin_unlock(&ctx->completion_lock);

    return io_flush_killed_timeouts(&list, -ECANCELED);
}
