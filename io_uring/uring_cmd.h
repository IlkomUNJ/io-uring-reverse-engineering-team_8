// SPDX-License-Identifier: GPL-2.0

#include <linux/io_uring/cmd.h>
#include <linux/io_uring_types.h>

/*
 * Structure: io_async_cmd
 * Purpose   : Stores asynchronous command details.
 *             - data: Internal command data used by the uring command.
 *             - vec : I/O vector for asynchronous I/O operations.
 *             - sqes: Array of two SQE entries cached for the command.
 */
struct io_async_cmd {
    struct io_uring_cmd_data    data;
    struct iou_vec          vec;
    struct io_uring_sqe     sqes[2];
};

/*
 * Function: io_uring_cmd
 * Purpose : Executes a previously prepared uring command.
 *           Processes the I/O request using the provided issue flags and returns a status.
 */
int io_uring_cmd(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Function: io_uring_cmd_prep
 * Purpose : Prepares a uring command by extracting necessary parameters from the SQE.
 *           Initializes the internal command data structures needed for asynchronous processing.
 */
int io_uring_cmd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_uring_cmd_cleanup
 * Purpose : Cleans up resources allocated for an asynchronous uring command.
 *           Releases memory associated with the asynchronous data and clears related flags.
 */
void io_uring_cmd_cleanup(struct io_kiocb *req);

/*
 * Function: io_uring_try_cancel_uring_cmd
 * Purpose : Attempts to cancel pending uring commands.
 *           Iterates through the commands in the cancelable list and cancels those that match
 *           the given criteria (based on the task context or if cancel_all is true).
 */
bool io_uring_try_cancel_uring_cmd(struct io_ring_ctx *ctx,
                   struct io_uring_task *tctx, bool cancel_all);

/*
 * Function: io_cmd_cache_free
 * Purpose : Frees a cache entry associated with an asynchronous uring command.
 *           Releases the I/O vector and then frees the allocated cache memory.
 */
void io_cmd_cache_free(const void *entry);

/*
 * Function: io_uring_cmd_import_fixed_vec
 * Purpose : Imports a fixed vector of user-supplied iovec structures into a uring command.
 *           Prepares and registers the asynchronous I/O vector based on the provided user vector.
 */
int io_uring_cmd_import_fixed_vec(struct io_uring_cmd *ioucmd,
                  const struct iovec __user *uvec,
                  size_t uvec_segs,
                  int ddir, struct iov_iter *iter,
                  unsigned issue_flags);
