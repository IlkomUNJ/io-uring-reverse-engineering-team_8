// SPDX-License-Identifier: GPL-2.0

/*
 * Function: io_tee_prep
 * Purpose  : Prepares a tee operation. 
 *            Validates the splice SQE parameters and initializes the request
 *            for a tee operation.
 */
int io_tee_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_tee
 * Purpose  : Executes a tee operation.
 *            Duplicates data from one pipe to another using the prepared request.
 */
int io_tee(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Function: io_splice_cleanup
 * Purpose  : Cleans up any resources allocated for a splice operation.
 *            Releases resource nodes or other allocations associated with the request.
 */
void io_splice_cleanup(struct io_kiocb *req);

/*
 * Function: io_splice_prep
 * Purpose  : Prepares a splice operation.
 *            Reads input/output offsets and other parameters from the SQE,
 *            then initializes the splice request.
 */
int io_splice_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_splice
 * Purpose  : Executes a splice operation.
 *            Transfers data between file descriptors and sets the request result.
 */
int io_splice(struct io_kiocb *req, unsigned int issue_flags);
