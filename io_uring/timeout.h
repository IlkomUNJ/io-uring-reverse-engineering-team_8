// SPDX-License-Identifier: GPL-2.0

/*
 * Structure: io_timeout_data
 * Purpose  : Contains asynchronous timeout information for an I/O request.
 *            - req: Pointer to the associated I/O request.
 *            - timer: High-resolution timer used to trigger the timeout event.
 *            - ts: The target timestamp for the timeout.
 *            - mode: The mode of the timer (absolute or relative).
 *            - flags: Flags to control timeout behavior (e.g. clock type, multishot).
 */
struct io_timeout_data {
    struct io_kiocb         *req;
    struct hrtimer          timer;
    struct timespec64       ts;
    enum hrtimer_mode       mode;
    u32                     flags;
};

/*
 * Function: __io_disarm_linked_timeout
 * Purpose  : Internal function to disarm (cancel) a linked timeout.
 *            Given a primary request and its linked timeout request, it attempts to cancel the timer.
 */
struct io_kiocb *__io_disarm_linked_timeout(struct io_kiocb *req,
                                            struct io_kiocb *link);

/*
 * Function: io_disarm_linked_timeout
 * Purpose  : Inline helper that checks whether the given request has a linked timeout
 *            (i.e. its link field is valid and its opcode equals IORING_OP_LINK_TIMEOUT).
 *            If so, it calls __io_disarm_linked_timeout; otherwise, returns NULL.
 */
static inline struct io_kiocb *io_disarm_linked_timeout(struct io_kiocb *req)
{
    struct io_kiocb *link = req->link;

    if (link && link->opcode == IORING_OP_LINK_TIMEOUT)
        return __io_disarm_linked_timeout(req, link);

    return NULL;
}

/*
 * Function: io_flush_timeouts
 * Purpose  : Flushes all pending timeout requests present in the I/O ring context.
 *            This __cold function is intended for infrequent use during cleanup.
 */
__cold void io_flush_timeouts(struct io_ring_ctx *ctx);

/* Forward declaration for io_cancel_data */
struct io_cancel_data;

/*
 * Function: io_timeout_cancel
 * Purpose  : Cancels a timeout request that matches the provided cancellation data.
 *            Returns 0 on success or a negative error code if no matching timeout is found.
 */
int io_timeout_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd);

/*
 * Function: io_kill_timeouts
 * Purpose  : Attempts to kill (cancel) one or more timeout requests within the context.
 *            If cancel_all is true, all matching timeouts are cancelled; otherwise, only those meeting criteria.
 *            Returns true if one or more timeouts were killed.
 */
__cold bool io_kill_timeouts(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
                             bool cancel_all);

/*
 * Function: io_queue_linked_timeout
 * Purpose  : Queues a linked timeout request for processing.
 *            This is used when a timeout is associated as part of a linked (chained) operation.
 */
void io_queue_linked_timeout(struct io_kiocb *req);

/*
 * Function: io_disarm_next
 * Purpose  : Disarms the next linked timeout request associated with the given I/O request.
 *            It cancels and removes the timeout from the chain as needed.
 */
void io_disarm_next(struct io_kiocb *req);

/*
 * Function: io_timeout_prep
 * Purpose  : Prepares a regular (non-linked) timeout request.
 *            Extracts timeout parameters from the submission queue entry (SQE) and sets up
 *            the I/O request's timeout data accordingly.
 * Returns  : 0 on success or a negative error code on failure.
 */
int io_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_link_timeout_prep
 * Purpose  : Prepares a linked timeout request.
 *            Similar to io_timeout_prep, but for requests that are linked to a previous timeout.
 * Returns  : 0 on success or a negative error code.
 */
int io_link_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_timeout
 * Purpose  : Executes the timeout request by starting the high-resolution timer.
 *            The function returns IOU_ISSUE_SKIP_COMPLETE to indicate that further submission
 *            processing for this request is skipped.
 */
int io_timeout(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Function: io_timeout_remove_prep
 * Purpose  : Prepares a timeout removal (or update) request.
 *            Extracts parameters from the SQE, validates them, and stores them in a dedicated structure.
 * Returns  : 0 on success or a negative error code if validation fails.
 */
int io_timeout_remove_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_timeout_remove
 * Purpose  : Removes or updates an existing timeout command.
 *            Depending on the flags, it either cancels the timeout or updates it with new parameters.
 *            Sets the result of the I/O request accordingly and returns IOU_OK.
 */
int io_timeout_remove(struct io_kiocb *req, unsigned int issue_flags);
