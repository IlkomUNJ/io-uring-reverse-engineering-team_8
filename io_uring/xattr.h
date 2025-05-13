// SPDX-License-Identifier: GPL-2.0

/*
 * Function: io_xattr_cleanup
 * Purpose : Frees resources allocated for an extended attribute (xattr) request.
 *           This includes releasing any allocated filename and freeing kernel buffers.
 */
void io_xattr_cleanup(struct io_kiocb *req);

/*
 * Function: io_fsetxattr_prep
 * Purpose : Prepares a fixed-buffer setxattr operation.
 *           Extracts and validates xattr parameters from the SQE for a fixed file.
 */
int io_fsetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_fsetxattr
 * Purpose : Executes a fixed-buffer setxattr operation.
 *           Sets the extended attribute on the fixed file and updates the request result.
 */
int io_fsetxattr(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Function: io_setxattr_prep
 * Purpose : Prepares a setxattr operation for non-fixed files.
 *           Extracts and validates the xattr parameters from the SQE and obtains the target filename.
 */
int io_setxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_setxattr
 * Purpose : Executes a setxattr operation for non-fixed files.
 *           Sets the extended attribute using the resolved filename and updates the request result.
 */
int io_setxattr(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Function: io_fgetxattr_prep
 * Purpose : Prepares a fixed-buffer getxattr operation.
 *           Extracts the required parameters from the SQE for retrieving xattr data.
 */
int io_fgetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_fgetxattr
 * Purpose : Executes a fixed-buffer getxattr operation.
 *           Retrieves the extended attribute from the fixed file and updates the request result.
 */
int io_fgetxattr(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Function: io_getxattr_prep
 * Purpose : Prepares a getxattr operation for non-fixed files.
 *           Extracts and validates xattr parameters from the SQE and fetches the target filename.
 */
int io_getxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_getxattr
 * Purpose : Executes a getxattr operation for non-fixed files.
 *           Retrieves the extended attribute using the resolved filename and updates the request result.
 */
int io_getxattr(struct io_kiocb *req, unsigned int issue_flags);
