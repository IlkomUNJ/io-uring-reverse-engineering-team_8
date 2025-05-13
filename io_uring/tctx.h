// SPDX-License-Identifier: GPL-2.0

/*
 * Structure: io_tctx_node
 * Purpose   : Represents a node linking an io_uring context (ctx) with a task.
 *             Used internally to manage task-to-io_uring associations.
 */
struct io_tctx_node {
    struct list_head    ctx_node;
    struct task_struct  *task;
    struct io_ring_ctx  *ctx;
};

/*
 * Function: io_uring_alloc_task_context
 * Purpose : Allocate and initialize an io_uring task context for the given task and context.
 * Returns : 0 on success, or a negative error code on failure.
 */
int io_uring_alloc_task_context(struct task_struct *task,
                struct io_ring_ctx *ctx);

/*
 * Function: io_uring_del_tctx_node
 * Purpose : Remove a task context node identified by the given index, cleaning up its resources.
 */
void io_uring_del_tctx_node(unsigned long index);

/*
 * Function: __io_uring_add_tctx_node
 * Purpose : Add a new task context node to the current task's io_uring context for the given context.
 * Returns : 0 on success, or a negative error code on failure.
 */
int __io_uring_add_tctx_node(struct io_ring_ctx *ctx);

/*
 * Function: __io_uring_add_tctx_node_from_submit
 * Purpose : Add a task context node triggered from a submit operation, possibly checking single issuer constraints.
 * Returns : 0 on success, or a negative error code on failure.
 */
int __io_uring_add_tctx_node_from_submit(struct io_ring_ctx *ctx);

/*
 * Function: io_uring_clean_tctx
 * Purpose : Clean up and free the io_uring task context, releasing any associated resources.
 */
void io_uring_clean_tctx(struct io_uring_task *tctx);

/*
 * Function: io_uring_unreg_ringfd
 * Purpose : Unregister all ring file descriptors associated with the current task's io_uring context.
 */
void io_uring_unreg_ringfd(void);

/*
 * Function: io_ringfd_register
 * Purpose : Register a ring file descriptor with the io_uring context. This caches the file to avoid repeated fd lookups.
 * Returns : The index where the file is registered on success, or a negative error code on failure.
 */
int io_ringfd_register(struct io_ring_ctx *ctx, void __user *__arg,
               unsigned nr_args);

/*
 * Function: io_ringfd_unregister
 * Purpose : Unregister ring file descriptors from the io_uring context.
 * Returns : The number of entries successfully unregistered, or a negative error code on failure.
 */
int io_ringfd_unregister(struct io_ring_ctx *ctx, void __user *__arg,
             unsigned nr_args);

/*
 * Inline Function: io_uring_add_tctx_node
 * Purpose : Add a task context node to the current task's io_uring context if it hasn't already been added.
 *           Returns 0 immediately if the current task context already maps the given io_uring context.
 */
static inline int io_uring_add_tctx_node(struct io_ring_ctx *ctx)
{
    struct io_uring_task *tctx = current->io_uring;

    if (likely(tctx && tctx->last == ctx))
        return 0;

    return __io_uring_add_tctx_node_from_submit(ctx);
}
