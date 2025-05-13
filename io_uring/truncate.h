// SPDX-License-Identifier: GPL-2.0

/*
 * Function: io_ftruncate_prep
 * Purpose  : Prepares a file truncation request by extracting the target truncation
 *            length from the provided SQE. It validates that no disallowed fields
 *            are set, and configures the I/O request accordingly.
 */
int io_ftruncate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_ftruncate
 * Purpose  : Executes a file truncation operation. It invokes the underlying
 *            do_ftruncate() using the length configured in the preparation step,
 *            sets the outcome for the request, and returns a completion status.
 */
int io_ftruncate(struct io_kiocb *req, unsigned int issue_flags);
