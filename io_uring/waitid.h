// SPDX-License-Identifier: GPL-2.0

#include "../kernel/exit.h"

/*
 * Structure: io_waitid_async
 * Purpose   : Holds asynchronous waitid operation data.
 *             - req: Reference to the associated I/O request.
 *             - wo: Wait options used for waiting on an event.
 */
struct io_waitid_async {
    struct io_kiocb *req;
    struct wait_opts wo;
};

/*
 * Function: io_waitid_prep
 * Purpose : Prepares a waitid request.
 *           Extracts the necessary parameters from the SQE and initializes
 *           the waitid request structure.
 */
int io_waitid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_waitid
 * Purpose : Executes a waitid operation.
 *           Waits for the specified event and completes the request accordingly.
 */
int io_waitid(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Function: io_waitid_cancel
 * Purpose : Attempts to cancel a pending waitid operation.
 *           Removes the waitid request from the cancellation list using the provided cancel data.
 */
int io_waitid_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
             unsigned int issue_flags);

/*
 * Function: io_waitid_remove_all
 * Purpose : Removes all waitid requests associated with a given task context.
 *           Useful for cleaning up pending waitid operations when canceling if needed.
 */
bool io_waitid_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
              bool cancel_all);
