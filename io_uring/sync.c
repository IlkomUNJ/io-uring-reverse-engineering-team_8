// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/io_uring.h>
#include <linux/fsnotify.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "sync.h"

/*
 * Structure: io_sync
 * Purpose   : Holds parameters required for synchronous operations such as fsync, fallocate,
 *             and sync_file_range. This includes a file pointer, offset, length, flags, and mode.
 */
struct io_sync {
    struct file         *file;
    loff_t              len;
    loff_t              off;
    int             flags;
    int             mode;
};

/*
 * Function: io_sfr_prep
 * Purpose : Prepares a synchronous file range operation.
 *           Validates that disallowed fields in the SQE are zero and initializes the io_sync structure
 *           with the offset, length, and sync range flags from the SQE.
 */
int io_sfr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
    struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);

    if (unlikely(sqe->addr || sqe->buf_index || sqe->splice_fd_in))
        return -EINVAL;

    sync->off = READ_ONCE(sqe->off);
    sync->len = READ_ONCE(sqe->len);
    sync->flags = READ_ONCE(sqe->sync_range_flags);
    req->flags |= REQ_F_FORCE_ASYNC;

    return 0;
}

/*
 * Function: io_sync_file_range
 * Purpose : Executes a synchronous file range operation using sync_file_range.
 *           It asserts that the operation runs in a blocking context, then invokes sync_file_range
 *           with the previously stored offset, length, and flags, and sets the result.
 */
int io_sync_file_range(struct io_kiocb *req, unsigned int issue_flags)
{
    struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);
    int ret;

    /* sync_file_range always requires a blocking context */
    WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

    ret = sync_file_range(req->file, sync->off, sync->len, sync->flags);
    io_req_set_res(req, ret, 0);
    return IOU_OK;
}

/*
 * Function: io_fsync_prep
 * Purpose : Prepares an fsync operation.
 *           Validates forbidden fields in the SQE, then initializes the io_sync structure
 *           with the fsync flags, offset, and length. Also ensures that only supported flags are used.
 */
int io_fsync_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
    struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);

    if (unlikely(sqe->addr || sqe->buf_index || sqe->splice_fd_in))
        return -EINVAL;

    sync->flags = READ_ONCE(sqe->fsync_flags);
    if (unlikely(sync->flags & ~IORING_FSYNC_DATASYNC))
        return -EINVAL;

    sync->off = READ_ONCE(sqe->off);
    sync->len = READ_ONCE(sqe->len);
    req->flags |= REQ_F_FORCE_ASYNC;
    return 0;
}

/*
 * Function: io_fsync
 * Purpose : Executes an fsync operation by flushing file data to disk.
 *           It calls vfs_fsync_range with the provided offset and length (or LLONG_MAX if necessary),
 *           ensuring the operation occurs in a blocking context, and then sets the request result.
 */
int io_fsync(struct io_kiocb *req, unsigned int issue_flags)
{
    struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);
    loff_t end = sync->off + sync->len;
    int ret;

    /* fsync always requires a blocking context */
    WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

    ret = vfs_fsync_range(req->file, sync->off, end > 0 ? end : LLONG_MAX,
                sync->flags & IORING_FSYNC_DATASYNC);
    io_req_set_res(req, ret, 0);
    return IOU_OK;
}

/*
 * Function: io_fallocate_prep
 * Purpose : Prepares a fallocate operation.
 *           Validates that disallowed fields in the SQE are zero, then initializes the io_sync structure
 *           with the offset, length (stored in 'addr'), and mode (stored in 'len') for the fallocate operation.
 */
int io_fallocate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
    struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);

    if (sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
        return -EINVAL;

    sync->off = READ_ONCE(sqe->off);
    sync->len = READ_ONCE(sqe->addr);
    sync->mode = READ_ONCE(sqe->len);
    req->flags |= REQ_F_FORCE_ASYNC;
    return 0;
}

/*
 * Function: io_fallocate
 * Purpose : Executes a fallocate operation.
 *           Ensures the operation occurs in a blocking context, calls vfs_fallocate with the
 *           mode, offset, and length from the io_sync structure, notifies file modifications if successful,
 *           and then sets the request result.
 */
int io_fallocate(struct io_kiocb *req, unsigned int issue_flags)
{
    struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);
    int ret;

    /* fallocate always requires a blocking context */
    WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

    ret = vfs_fallocate(req->file, sync->mode, sync->off, sync->len);
    if (ret >= 0)
        fsnotify_modify(req->file);
    io_req_set_res(req, ret, 0);
    return IOU_OK;
}
