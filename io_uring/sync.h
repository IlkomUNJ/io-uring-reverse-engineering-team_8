// SPDX-License-Identifier: GPL-2.0

/*
 * Function: io_sfr_prep
 * Purpose  : Prepares a synchronous file-range (sfr) operation.
 *            It extracts the offset, length, and sync_range flags from the SQE,
 *            performs validation on disallowed fields, and marks the request for asynchronous processing.
 */
int io_sfr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_sync_file_range
 * Purpose  : Executes a synchronous file-range operation.
 *            It calls sync_file_range() on the file with the parameters extracted
 *            during preparation and sets the request result.
 */
int io_sync_file_range(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Function: io_fsync_prep
 * Purpose  : Prepares an fsync operation.
 *            It extracts the fsync flags, offset, and length from the SQE and validates fields.
 *            The request is then marked for asynchronous processing.
 */
int io_fsync_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_fsync
 * Purpose  : Executes an fsync operation.
 *            It invokes vfs_fsync_range() to ensure file data is flushed to disk,
 *            and then sets the result in the I/O request.
 */
int io_fsync(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Function: io_fallocate
 * Purpose  : Executes a fallocate operation.
 *            It uses the parameters stored in the request (mode, offset, length)
 *            to adjust the file's allocated space and notifies file modifications.
 */
int io_fallocate(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Function: io_fallocate_prep
 * Purpose  : Prepares a fallocate operation.
 *            It extracts the offset, length (from the 'addr' field), and mode (from the 'len' field)
 *            from the SQE, and marks the request for asynchronous processing.
 */
int io_fallocate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
