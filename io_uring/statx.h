// SPDX-License-Identifier: GPL-2.0

/*
 * Function: io_statx_prep
 * Purpose : Prepares a statx operation by extracting necessary parameters
 *           from the SQE and initializing the corresponding io_statx structure.
 */
int io_statx_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_statx
 * Purpose : Executes the statx operation using the parameters prepared earlier.
 *           It invokes the statx system call to retrieve file status information
 *           and sets the result on the I/O request.
 */
int io_statx(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Function: io_statx_cleanup
 * Purpose : Cleans up resources allocated for a statx operation.
 *           This function releases any memory or resource held in the io_statx structure.
 */
void io_statx_cleanup(struct io_kiocb *req);
