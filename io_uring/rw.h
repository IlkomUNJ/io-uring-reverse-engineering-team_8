// SPDX-License-Identifier: GPL-2.0

#include <linux/io_uring_types.h>
#include <linux/pagemap.h>

/*
 * Structure: io_meta_state
 * Purpose    : Stores metadata state for direct I/O operations, including a seed
 *              and an iterator state for the I/O vector.
 */
struct io_meta_state {
    u32         seed;
    struct iov_iter_state   iter_meta;
};

/*
 * Structure: io_async_rw
 * Purpose    : Describes asynchronous read/write operations.
 *              It holds the I/O vector, a counter for bytes done, and additional
 *              fields for iterator state, fast I/O vector, and either buffered I/O
 *              (wait_page_queue) or direct I/O (uio_meta and meta_state).
 * Note       : The fields within the struct_group(clear, ...) will be cleared.
 */
struct io_async_rw {
    struct iou_vec          vec;
    size_t              bytes_done;

    struct_group(clear,
        struct iov_iter         iter;
        struct iov_iter_state       iter_state;
        struct iovec            fast_iov;
        /*
         * wpq is for buffered I/O, while meta fields are used with direct I/O
         */
        union {
            struct wait_page_queue      wpq;
            struct {
                struct uio_meta         meta;
                struct io_meta_state        meta_state;
            };
        };
    );
};

/*
 * Function: io_prep_read_fixed
 * Purpose : Prepare a read operation using fixed buffers.
 *           Initializes the asynchronous read request based on the provided SQE.
 */
int io_prep_read_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_prep_write_fixed
 * Purpose : Prepare a write operation using fixed buffers.
 *           Sets up the asynchronous write request based on the provided SQE.
 */
int io_prep_write_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_prep_readv_fixed
 * Purpose : Prepare a vectored read (readv) operation using fixed buffers.
 *           Configures the asynchronous request for reading into multiple buffers.
 */
int io_prep_readv_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_prep_writev_fixed
 * Purpose : Prepare a vectored write (writev) operation using fixed buffers.
 *           Configures the asynchronous request for writing from multiple buffers.
 */
int io_prep_writev_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_prep_readv
 * Purpose : Prepare a vectored read (readv) operation using non-fixed buffers.
 *           Extracts vector parameters from the SQE and sets up the request.
 */
int io_prep_readv(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_prep_writev
 * Purpose : Prepare a vectored write (writev) operation using non-fixed buffers.
 *           Extracts vector parameters from the SQE and sets up the request.
 */
int io_prep_writev(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_prep_read
 * Purpose : Prepare a single-buffer read operation.
 *           Extracts the buffer address, length, and other parameters from the SQE.
 */
int io_prep_read(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_prep_write
 * Purpose : Prepare a single-buffer write operation.
 *           Extracts the relevant parameters from the SQE and sets up the request.
 */
int io_prep_write(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_read
 * Purpose : Execute a prepared read operation.
 *           Performs the actual reading from a file or device and sets the request result.
 */
int io_read(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Function: io_write
 * Purpose : Execute a prepared write operation.
 *           Performs the actual writing to a file or device and updates the request result.
 */
int io_write(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Function: io_read_fixed
 * Purpose : Execute a fixed-buffer read operation.
 *           Completes the read request and returns the appropriate result.
 */
int io_read_fixed(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Function: io_write_fixed
 * Purpose : Execute a fixed-buffer write operation.
 *           Completes the write request and returns the corresponding result.
 */
int io_write_fixed(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Function: io_readv_writev_cleanup
 * Purpose : Clean up resources allocated for readv/writev operations.
 *           Releases any temporary buffers or state associated with the request.
 */
void io_readv_writev_cleanup(struct io_kiocb *req);

/*
 * Function: io_rw_fail
 * Purpose : Handle failure in read/write operations.
 *           Sets error codes and performs necessary cleanup.
 */
void io_rw_fail(struct io_kiocb *req);

/*
 * Function: io_req_rw_complete
 * Purpose : Complete an asynchronous read/write request.
 *           Invokes the task work callback to finish the operation and signal completion.
 */
void io_req_rw_complete(struct io_kiocb *req, io_tw_token_t tw);

/*
 * Function: io_read_mshot_prep
 * Purpose : Prepare a multi-shot (repeated) read operation.
 *           Configures the request for repeated reads as indicated by the SQE.
 */
int io_read_mshot_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Function: io_read_mshot
 * Purpose : Execute a multi-shot read operation.
 *           Handles multiple read iterations within a single request and returns the status.
 */
int io_read_mshot(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Function: io_rw_cache_free
 * Purpose : Free cache entries for asynchronous read/write operations.
 *           Releases cached data structures when they are no longer needed.
 */
void io_rw_cache_free(const void *entry);
