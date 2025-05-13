// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/nospec.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "tctx.h"

/*
 * Function: io_init_wq_offload
 * Purpose : Initializes an offload work queue for io_uring.
 *           It checks for an existing hash map in the context; if none exists,
 *           it allocates one, sets the reference count to 1, and initializes its wait queue.
 *           Then, it prepares the work queue data (associating the hash and task) and
 *           creates an io_wq with a concurrency defined as the minimum of the number of SQ entries
 *           and 4 times the number of online CPUs.
 */
static struct io_wq *io_init_wq_offload(struct io_ring_ctx *ctx,
                    struct task_struct *task)
{
    struct io_wq_hash *hash;
    struct io_wq_data data;
    unsigned int concurrency;

    mutex_lock(&ctx->uring_lock);
    hash = ctx->hash_map;
    if (!hash) {
        hash = kzalloc(sizeof(*hash), GFP_KERNEL);
        if (!hash) {
            mutex_unlock(&ctx->uring_lock);
            return ERR_PTR(-ENOMEM);
        }
        refcount_set(&hash->refs, 1);
        init_waitqueue_head(&hash->wait);
        ctx->hash_map = hash;
    }
    mutex_unlock(&ctx->uring_lock);

    data.hash = hash;
    data.task = task;
    data.free_work = io_wq_free_work;
    data.do_work = io_wq_submit_work;

    /* Determine the concurrency: the minimum of the number of SQ entries and 4 * number of online CPUs */
    concurrency = min(ctx->sq_entries, 4 * num_online_cpus());

    return io_wq_create(concurrency, &data);
}

/*
 * Function: __io_uring_free
 * Purpose : Frees the io_uring task context associated with a task.
 *           Iterates over the xarray (xa) to verify no nodes remain, warns if any are found,
 *           destroys the percpu counter, frees the task context and resets the task's io_uring pointer.
 */
void __io_uring_free(struct task_struct *tsk)
{
    struct io_uring_task *tctx = tsk->io_uring;
    struct io_tctx_node *node;
    unsigned long index;

    xa_for_each(&tctx->xa, index, node) {
        WARN_ON_ONCE(1);
        break;
    }
    WARN_ON_ONCE(tctx->io_wq);
    WARN_ON_ONCE(tctx->cached_refs);

    percpu_counter_destroy(&tctx->inflight);
    kfree(tctx);
    tsk->io_uring = NULL;
}

/*
 * Function: io_uring_alloc_task_context
 * Purpose : Allocates and initializes an io_uring_task context for the given task and io_uring context.
 *           It allocates the task context structure, initializes a percpu counter,
 *           creates an offload work queue (via io_init_wq_offload), and sets up the xarray,
 *           wait queue, and task work callback used for asynchronous command handling.
 */
__cold int io_uring_alloc_task_context(struct task_struct *task,
                       struct io_ring_ctx *ctx)
{
    struct io_uring_task *tctx;
    int ret;

    tctx = kzalloc(sizeof(*tctx), GFP_KERNEL);
    if (unlikely(!tctx))
        return -ENOMEM;

    ret = percpu_counter_init(&tctx->inflight, 0, GFP_KERNEL);
    if (unlikely(ret)) {
        kfree(tctx);
        return ret;
    }

    tctx->io_wq = io_init_wq_offload(ctx, task);
    if (IS_ERR(tctx->io_wq)) {
        ret = PTR_ERR(tctx->io_wq);
        percpu_counter_destroy(&tctx->inflight);
        kfree(tctx);
        return ret;
    }

    tctx->task = task;
    xa_init(&tctx->xa);
    init_waitqueue_head(&tctx->wait);
    atomic_set(&tctx->in_cancel, 0);
    atomic_set(&tctx->inflight_tracked, 0);
    task->io_uring = tctx;
    init_llist_head(&tctx->task_list);
    init_task_work(&tctx->task_work, tctx_task_work);
    return 0;
}

/*
 * Function: __io_uring_add_tctx_node
 * Purpose : Adds a new context node linking the io_uring context (ctx) to the current task's io_uring_task.
 *           If the current task does not yet have an io_uring task context, it allocates one.
 *           Then, if a node for the given ctx is not already stored in the xarray, a new node is allocated and stored.
 */
int __io_uring_add_tctx_node(struct io_ring_ctx *ctx)
{
    struct io_uring_task *tctx = current->io_uring;
    struct io_tctx_node *node;
    int ret;

    if (unlikely(!tctx)) {
        ret = io_uring_alloc_task_context(current, ctx);
        if (unlikely(ret))
            return ret;

        tctx = current->io_uring;
        if (ctx->iowq_limits_set) {
            unsigned int limits[2] = { ctx->iowq_limits[0],
                           ctx->iowq_limits[1], };

            ret = io_wq_max_workers(tctx->io_wq, limits);
            if (ret)
                return ret;
        }
    }
    if (!xa_load(&tctx->xa, (unsigned long)ctx)) {
        node = kmalloc(sizeof(*node), GFP_KERNEL);
        if (!node)
            return -ENOMEM;
        node->ctx = ctx;
        node->task = current;

        ret = xa_err(xa_store(&tctx->xa, (unsigned long)ctx,
                    node, GFP_KERNEL));
        if (ret) {
            kfree(node);
            return ret;
        }

        mutex_lock(&ctx->uring_lock);
        list_add(&node->ctx_node, &ctx->tctx_list);
        mutex_unlock(&ctx->uring_lock);
    }
    return 0;
}

/*
 * Function: __io_uring_add_tctx_node_from_submit
 * Purpose : A wrapper that adds a tctx node when a submission occurs.
 *           It also ensures that if IORING_SETUP_SINGLE_ISSUER is set, only the submitter task is allowed.
 *           On success, it stores the current io_uring context as the 'last' context.
 */
int __io_uring_add_tctx_node_from_submit(struct io_ring_ctx *ctx)
{
    int ret;

    if (ctx->flags & IORING_SETUP_SINGLE_ISSUER
        && ctx->submitter_task != current)
        return -EEXIST;

    ret = __io_uring_add_tctx_node(ctx);
    if (ret)
        return ret;

    current->io_uring->last = ctx;
    return 0;
}

/*
 * Function: io_uring_del_tctx_node
 * Purpose : Removes the tctx node corresponding to the given index from the current task's io_uring context.
 *           It asserts that the current task owns the node, removes the node from the context list, and frees it.
 */
__cold void io_uring_del_tctx_node(unsigned long index)
{
    struct io_uring_task *tctx = current->io_uring;
    struct io_tctx_node *node;

    if (!tctx)
        return;
    node = xa_erase(&tctx->xa, index);
    if (!node)
        return;

    WARN_ON_ONCE(current != node->task);
    WARN_ON_ONCE(list_empty(&node->ctx_node));

    mutex_lock(&node->ctx->uring_lock);
    list_del(&node->ctx_node);
    mutex_unlock(&node->ctx->uring_lock);

    if (tctx->last == node->ctx)
        tctx->last = NULL;
    kfree(node);
}

/*
 * Function: io_uring_clean_tctx
 * Purpose : Cleans up and shuts down the current task's io_uring context.
 *           Iterates over all stored tctx nodes, removes them, and then
 *           calls io_wq_put_and_exit() to properly clean up the associated work queue.
 */
__cold void io_uring_clean_tctx(struct io_uring_task *tctx)
{
    struct io_wq *wq = tctx->io_wq;
    struct io_tctx_node *node;
    unsigned long index;

    xa_for_each(&tctx->xa, index, node) {
        io_uring_del_tctx_node(index);
        cond_resched();
    }
    if (wq) {
        /*
         * Must be after io_uring_del_tctx_node() (removes nodes under
         * uring_lock) to avoid race with io_uring_try_cancel_iowq().
         */
        io_wq_put_and_exit(wq);
        tctx->io_wq = NULL;
    }
}

/*
 * Function: io_uring_unreg_ringfd
 * Purpose : Unregisters all ring file descriptors associated with the current task's io_uring context.
 *           Iterates over the registered rings and calls fput() on each, then resets the slot to NULL.
 */
void io_uring_unreg_ringfd(void)
{
    struct io_uring_task *tctx = current->io_uring;
    int i;

    for (i = 0; i < IO_RINGFD_REG_MAX; i++) {
        if (tctx->registered_rings[i]) {
            fput(tctx->registered_rings[i]);
            tctx->registered_rings[i] = NULL;
        }
    }
}

/*
 * Function: io_ring_add_registered_file
 * Purpose : Registers a file in the io_uring task context to avoid repeated fdget/fdput calls.
 *           Scans for a free slot between the indices 'start' and 'end' and registers the file there.
 *           Returns the registered slot index on success or -EBUSY if no slot is available.
 */
int io_ring_add_registered_file(struct io_uring_task *tctx, struct file *file,
                     int start, int end)
{
    int offset;
    for (offset = start; offset < end; offset++) {
        offset = array_index_nospec(offset, IO_RINGFD_REG_MAX);
        if (tctx->registered_rings[offset])
            continue;

        tctx->registered_rings[offset] = file;
        return offset;
    }
    return -EBUSY;
}

/*
 * Function: io_ring_add_registered_fd
 * Purpose : Retrieves a file from the given file descriptor and registers it in the io_uring task context.
 *           If the file descriptor is valid and supports io_uring operations, it registers the file.
 *           Returns the slot index on success, or an appropriate error code.
 */
static int io_ring_add_registered_fd(struct io_uring_task *tctx, int fd,
                     int start, int end)
{
    struct file *file;
    int offset;

    file = fget(fd);
    if (!file) {
        return -EBADF;
    } else if (!io_is_uring_fops(file)) {
        fput(file);
        return -EOPNOTSUPP;
    }
    offset = io_ring_add_registered_file(tctx, file, start, end);
    if (offset < 0)
        fput(file);
    return offset;
}

/*
 * Function: io_ringfd_register
 * Purpose : Registers ring file descriptors to cache them for io_uring_enter() calls.
 *           It copies an array of io_uring_rsrc_update structures from user-space,
 *           registers each provided ring file descriptor, and writes the updated registration info back to user-space.
 *           Returns the number of entries successfully processed, or an error code if none were processed.
 */
int io_ringfd_register(struct io_ring_ctx *ctx, void __user *__arg,
               unsigned nr_args)
{
    struct io_uring_rsrc_update __user *arg = __arg;
    struct io_uring_rsrc_update reg;
    struct io_uring_task *tctx;
    int ret, i;

    if (!nr_args || nr_args > IO_RINGFD_REG_MAX)
        return -EINVAL;

    mutex_unlock(&ctx->uring_lock);
    ret = __io_uring_add_tctx_node(ctx);
    mutex_lock(&ctx->uring_lock);
    if (ret)
        return ret;

    tctx = current->io_uring;
    for (i = 0; i < nr_args; i++) {
        int start, end;

        if (copy_from_user(&reg, &arg[i], sizeof(reg))) {
            ret = -EFAULT;
            break;
        }

        if (reg.resv) {
            ret = -EINVAL;
            break;
        }

        if (reg.offset == -1U) {
            start = 0;
            end = IO_RINGFD_REG_MAX;
        } else {
            if (reg.offset >= IO_RINGFD_REG_MAX) {
                ret = -EINVAL;
                break;
            }
            start = reg.offset;
            end = start + 1;
        }

        ret = io_ring_add_registered_fd(tctx, reg.data, start, end);
        if (ret < 0)
            break;

        reg.offset = ret;
        if (copy_to_user(&arg[i], &reg, sizeof(reg))) {
            fput(tctx->registered_rings[reg.offset]);
            tctx->registered_rings[reg.offset] = NULL;
            ret = -EFAULT;
            break;
        }
    }

    return i ? i : ret;
}

/*
 * Function: io_ringfd_unregister
 * Purpose : Unregisters ring file descriptors specified by user-space.
 *           Reads an array of io_uring_rsrc_update structures from user-space and, for each valid registration,
 *           calls fput() on the corresponding registered ring, then clears the slot.
 *           Returns the number of entries successfully unregistered or an error code.
 */
int io_ringfd_unregister(struct io_ring_ctx *ctx, void __user *__arg,
             unsigned nr_args)
{
    struct io_uring_rsrc_update __user *arg = __arg;
    struct io_uring_task *tctx = current->io_uring;
    struct io_uring_rsrc_update reg;
    int ret = 0, i;

    if (!nr_args || nr_args > IO_RINGFD_REG_MAX)
        return -EINVAL;
    if (!tctx)
        return 0;

    for (i = 0; i < nr_args; i++) {
        if (copy_from_user(&reg, &arg[i], sizeof(reg))) {
            ret = -EFAULT;
            break;
        }
        if (reg.resv || reg.data || reg.offset >= IO_RINGFD_REG_MAX) {
            ret = -EINVAL;
            break;
        }

        reg.offset = array_index_nospec(reg.offset, IO_RINGFD_REG_MAX);
        if (tctx->registered_rings[reg.offset]) {
            fput(tctx->registered_rings[reg.offset]);
            tctx->registered_rings[reg.offset] = NULL;
        }
    }

    return i ? i : ret;
}
