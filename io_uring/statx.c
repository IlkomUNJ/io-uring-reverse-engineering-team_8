// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "../fs/internal.h"

#include "io_uring.h"
#include "statx.h"

/*
 * Structure: io_statx
 * Purpose   : Holds parameters for a statx operation including:
 *             - file: the file pointer associated with the operation
 *             - dfd: the directory file descriptor for relative path lookups
 *             - mask: bitmask specifying which statx fields to fetch
 *             - flags: flags controlling the statx behavior
 *             - filename: pointer to the resolved filename structure
 *             - buffer: user-space pointer for storing the statx result
 */
struct io_statx {
    struct file         *file;
    int             dfd;
    unsigned int            mask;
    unsigned int            flags;
    struct filename         *filename;
    struct statx __user     *buffer;
};

/*
 * Function: io_statx_prep
 * Purpose : Prepare a statx operation by extracting parameters from the SQE.
 *           Validates that disallowed fields are zero and that a fixed file is not used.
 *           It reads the directory file descriptor, mask, and pointer values from the SQE,
 *           resolves the filename with proper flags, and marks the request for asynchronous cleanup.
 */
int io_statx_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
    struct io_statx *sx = io_kiocb_to_cmd(req, struct io_statx);
    const char __user *path;

    if (sqe->buf_index || sqe->splice_fd_in)
        return -EINVAL;
    if (req->flags & REQ_F_FIXED_FILE)
        return -EBADF;

    sx->dfd = READ_ONCE(sqe->fd);
    sx->mask = READ_ONCE(sqe->len);
    path = u64_to_user_ptr(READ_ONCE(sqe->addr));
    sx->buffer = u64_to_user_ptr(READ_ONCE(sqe->addr2));
    sx->flags = READ_ONCE(sqe->statx_flags);

    sx->filename = getname_uflags(path, sx->flags);

    if (IS_ERR(sx->filename)) {
        int ret = PTR_ERR(sx->filename);

        sx->filename = NULL;
        return ret;
    }

    req->flags |= REQ_F_NEED_CLEANUP;
    req->flags |= REQ_F_FORCE_ASYNC;
    return 0;
}

/*
 * Function: io_statx
 * Purpose : Execute the statx operation using the parameters prepared earlier.
 *           It calls do_statx with the directory fd, filename, flags, mask, and buffer,
 *           sets the request result, and returns the IOU_OK status.
 */
int io_statx(struct io_kiocb *req, unsigned int issue_flags)
{
    struct io_statx *sx = io_kiocb_to_cmd(req, struct io_statx);
    int ret;

    WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

    ret = do_statx(sx->dfd, sx->filename, sx->flags, sx->mask, sx->buffer);
    io_req_set_res(req, ret, 0);
    return IOU_OK;
}

/*
 * Function: io_statx_cleanup
 * Purpose : Clean up any resources allocated during statx preparation.
 *           Releases the filename resource if it was allocated.
 */
void io_statx_cleanup(struct io_kiocb *req)
{
    struct io_statx *sx = io_kiocb_to_cmd(req, struct io_statx);

    if (sx->filename)
        putname(sx->filename);
}
