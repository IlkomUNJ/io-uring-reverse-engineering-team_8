// SPDX-License-Identifier: GPL-2.0
/*
 * Support for async notification of waitid
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/compat.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "cancel.h"
#include "waitid.h"
#include "../kernel/exit.h"

static void io_waitid_cb(struct io_kiocb *req, io_tw_token_t tw);

#define IO_WAITID_CANCEL_FLAG   BIT(31)
#define IO_WAITID_REF_MASK  GENMASK(30, 0)

struct io_waitid {
    struct file         *file;
    int             which;
    pid_t               upid;
    int             options;
    atomic_t            refs;
    struct wait_queue_head      *head;
    struct siginfo __user       *infop;
    struct waitid_info      info;
};

/*
 * Function: io_waitid_free
 * Purpose : Cleans up the waitid async data.
 *           Releases the reference to the PID and frees the asynchronous data,
 *           then clears the REQ_F_ASYNC_DATA flag.
 */
static void io_waitid_free(struct io_kiocb *req)
{
    struct io_waitid_async *iwa = req->async_data;

    put_pid(iwa->wo.wo_pid);
    kfree(req->async_data);
    req->async_data = NULL;
    req->flags &= ~REQ_F_ASYNC_DATA;
}

/*
 * Function: io_waitid_compat_copy_si
 * Purpose : Copies siginfo data using the compat_siginfo (32-bit)
 *           user-space interface. Writes signal number and associated fields.
 */
static bool io_waitid_compat_copy_si(struct io_waitid *iw, int signo)
{
    struct compat_siginfo __user *infop;
    bool ret;

    infop = (struct compat_siginfo __user *) iw->infop;

    if (!user_write_access_begin(infop, sizeof(*infop)))
        return false;

    unsafe_put_user(signo, &infop->si_signo, Efault);
    unsafe_put_user(0, &infop->si_errno, Efault);
    unsafe_put_user(iw->info.cause, &infop->si_code, Efault);
    unsafe_put_user(iw->info.pid, &infop->si_pid, Efault);
    unsafe_put_user(iw->info.uid, &infop->si_uid, Efault);
    unsafe_put_user(iw->info.status, &infop->si_status, Efault);
    ret = true;
done:
    user_write_access_end();
    return ret;
Efault:
    ret = false;
    goto done;
}

/*
 * Function: io_waitid_copy_si
 * Purpose : Copies siginfo data for a waitid request into user memory.
 *           Chooses between compat and native copy routines based on the context.
 */
static bool io_waitid_copy_si(struct io_kiocb *req, int signo)
{
    struct io_waitid *iw = io_kiocb_to_cmd(req, struct io_waitid);
    bool ret;

    if (!iw->infop)
        return true;

    if (io_is_compat(req->ctx))
        return io_waitid_compat_copy_si(iw, signo);

    if (!user_write_access_begin(iw->infop, sizeof(*iw->infop)))
        return false;

    unsafe_put_user(signo, &iw->infop->si_signo, Efault);
    unsafe_put_user(0, &iw->infop->si_errno, Efault);
    unsafe_put_user(iw->info.cause, &iw->infop->si_code, Efault);
    unsafe_put_user(iw->info.pid, &iw->infop->si_pid, Efault);
    unsafe_put_user(iw->info.uid, &iw->infop->si_uid, Efault);
    unsafe_put_user(iw->info.status, &iw->infop->si_status, Efault);
    ret = true;
done:
    user_write_access_end();
    return ret;
Efault:
    ret = false;
    goto done;
}

/*
 * Function: io_waitid_finish
 * Purpose : Finalizes the waitid operation.
 *           Determines the appropriate signal (SIGCHLD if ret > 0),
 *           copies the siginfo to user space, frees async data, and returns the result.
 */
static int io_waitid_finish(struct io_kiocb *req, int ret)
{
    int signo = 0;

    if (ret > 0) {
        signo = SIGCHLD;
        ret = 0;
    }

    if (!io_waitid_copy_si(req, signo))
        ret = -EFAULT;
    io_waitid_free(req);
    return ret;
}

/*
 * Function: io_waitid_complete
 * Purpose : Completes a waitid request.
 *           Ensures that a reference is held, removes the request from its hash list,
 *           finalizes the waitid operation, and sets the result for the I/O request.
 */
static void io_waitid_complete(struct io_kiocb *req, int ret)
{
    struct io_waitid *iw = io_kiocb_to_cmd(req, struct io_waitid);

    /* anyone completing better be holding a reference */
    WARN_ON_ONCE(!(atomic_read(&iw->refs) & IO_WAITID_REF_MASK));

    lockdep_assert_held(&req->ctx->uring_lock);

    hlist_del_init(&req->hash_node);

    ret = io_waitid_finish(req, ret);
    if (ret < 0)
        req_set_fail(req);
    io_req_set_res(req, ret, 0);
}

/*
 * Function: __io_waitid_cancel
 * Purpose : Attempts to cancel a pending waitid request.
 *           Marks the request as canceled by setting IO_WAITID_CANCEL_FLAG,
 *           claims ownership, removes the wait node from the wait queue,
 *           and completes the request with a cancellation error.
 */
static bool __io_waitid_cancel(struct io_kiocb *req)
{
    struct io_waitid *iw = io_kiocb_to_cmd(req, struct io_waitid);
    struct io_waitid_async *iwa = req->async_data;

    /*
     * Mark us canceled regardless of ownership. This will prevent a
     * potential retry from a spurious wakeup.
     */
    atomic_or(IO_WAITID_CANCEL_FLAG, &iw->refs);

    /* claim ownership */
    if (atomic_fetch_inc(&iw->refs) & IO_WAITID_REF_MASK)
        return false;

    spin_lock_irq(&iw->head->lock);
    list_del_init(&iwa->wo.child_wait.entry);
    spin_unlock_irq(&iw->head->lock);
    io_waitid_complete(req, -ECANCELED);
    io_req_queue_tw_complete(req, -ECANCELED);
    return true;
}

/*
 * Function: io_waitid_cancel
 * Purpose : Cancels a waitid request.
 *           Initiates cancellation by removing the request from the waitid list using the helper __io_waitid_cancel.
 */
int io_waitid_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
             unsigned int issue_flags)
{
    return io_cancel_remove(ctx, cd, issue_flags, &ctx->waitid_list, __io_waitid_cancel);
}

/*
 * Function: io_waitid_remove_all
 * Purpose : Cancels all waitid requests associated with a given task context.
 *           Uses a helper to remove all entries from the waitid list.
 */
bool io_waitid_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
              bool cancel_all)
{
    return io_cancel_remove_all(ctx, tctx, &ctx->waitid_list, cancel_all, __io_waitid_cancel);
}

/*
 * Function: io_waitid_drop_issue_ref
 * Purpose : Drops a reference under a race with wakeup callbacks.
 *           Decrements the reference counter; if a racing wakeup is detected,
 *           queues task work to complete the request.
 */
static inline bool io_waitid_drop_issue_ref(struct io_kiocb *req)
{
    struct io_waitid *iw = io_kiocb_to_cmd(req, struct io_waitid);
    struct io_waitid_async *iwa = req->async_data;

    if (!atomic_sub_return(1, &iw->refs))
        return false;

    /*
     * Wakeup triggered, racing with us. It was prevented from
     * completing because of that, queue up the task work to complete the request.
     */
    req->io_task_work.func = io_waitid_cb;
    io_req_task_work_add(req);
    remove_wait_queue(iw->head, &iwa->wo.child_wait);
    return true;
}

/*
 * Function: io_waitid_cb
 * Purpose : Task work callback invoked for waitid requests.
 *           Locks the task work, re-checks the wait condition via __do_wait(),
 *           re-arms the wait if necessary, or completes the request if the wait condition is met.
 */
static void io_waitid_cb(struct io_kiocb *req, io_tw_token_t tw)
{
    struct io_waitid_async *iwa = req->async_data;
    struct io_ring_ctx *ctx = req->ctx;
    int ret;

    io_tw_lock(ctx, tw);

    ret = __do_wait(&iwa->wo);

    /*
     * If we get -ERESTARTSYS here, we need to re-arm and check again
     * to ensure we get another callback. If the retry works, then we can
     * just remove ourselves from the waitqueue again and finish the request.
     */
    if (unlikely(ret == -ERESTARTSYS)) {
        struct io_waitid *iw = io_kiocb_to_cmd(req, struct io_waitid);

        /* Don't retry if cancellation occurred meanwhile */
        ret = -ECANCELED;
        if (!(atomic_read(&iw->refs) & IO_WAITID_CANCEL_FLAG)) {
            iw->head = &current->signal->wait_chldexit;
            add_wait_queue(iw->head, &iwa->wo.child_wait);
            ret = __do_wait(&iwa->wo);
            if (ret == -ERESTARTSYS) {
                /* Retry armed, drop our reference and exit */
                io_waitid_drop_issue_ref(req);
                return;
            }

            remove_wait_queue(iw->head, &iwa->wo.child_wait);
        }
    }

    io_waitid_complete(req, ret);
    io_req_task_complete(req, tw);
}

/*
 * Function: io_waitid_wait
 * Purpose : Wait queue callback for a waitid request.
 *           Checks if the given task should wake the wait condition;
 *           if so, claims ownership and triggers processing of the waitid request.
 */
static int io_waitid_wait(struct wait_queue_entry *wait, unsigned mode,
              int sync, void *key)
{
    struct wait_opts *wo = container_of(wait, struct wait_opts, child_wait);
    struct io_waitid_async *iwa = container_of(wo, struct io_waitid_async, wo);
    struct io_kiocb *req = iwa->req;
    struct io_waitid *iw = io_kiocb_to_cmd(req, struct io_waitid);
    struct task_struct *p = key;

    if (!pid_child_should_wake(wo, p))
        return 0;

    /* Cancel is in progress; increment ref count and signal wakeup */
    if (atomic_fetch_inc(&iw->refs) & IO_WAITID_REF_MASK)
        return 1;

    req->io_task_work.func = io_waitid_cb;
    io_req_task_work_add(req);
    list_del_init(&wait->entry);
    return 1;
}

/*
 * Function: io_waitid_prep
 * Purpose : Prepares a waitid request.
 *           Validates that disallowed SQE fields are zero,
 *           extracts parameters (which, upid, options, and user siginfo pointer)
 *           from the SQE, and allocates asynchronous data.
 */
int io_waitid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
    struct io_waitid *iw = io_kiocb_to_cmd(req, struct io_waitid);
    struct io_waitid_async *iwa;

    if (sqe->addr || sqe->buf_index || sqe->addr3 || sqe->waitid_flags)
        return -EINVAL;

    iwa = io_uring_alloc_async_data(NULL, req);
    if (!unlikely(iwa))
        return -ENOMEM;
    iwa->req = req;

    iw->which = READ_ONCE(sqe->len);
    iw->upid = READ_ONCE(sqe->fd);
    iw->options = READ_ONCE(sqe->file_index);
    iw->infop = u64_to_user_ptr(READ_ONCE(sqe->addr2));
    return 0;
}

/*
 * Function: io_waitid
 * Purpose : Executes a waitid request.
 *           Prepares the kernel wait using kernel_waitid_prepare(), marks the request as busy,
 *           adds it to the waitid list, and sets up the wait queue callback.
 *           Handles -ERESTARTSYS by dropping a reference or deferring completion,
 *           and finally cleans up.
 */
int io_waitid(struct io_kiocb *req, unsigned int issue_flags)
{
    struct io_waitid *iw = io_kiocb_to_cmd(req, struct io_waitid);
    struct io_waitid_async *iwa = req->async_data;
    struct io_ring_ctx *ctx = req->ctx;
    int ret;

    ret = kernel_waitid_prepare(&iwa->wo, iw->which, iw->upid, &iw->info,
                    iw->options, NULL);
    if (ret)
        goto done;

    /*
     * Mark the request as busy upfront to handle race with wakeup.
     */
    atomic_set(&iw->refs, 1);

    /*
     * Cancel must be safe; add the request to the waitid list while holding the lock.
     */
    io_ring_submit_lock(ctx, issue_flags);
    hlist_add_head(&req->hash_node, &ctx->waitid_list);

    init_waitqueue_func_entry(&iwa->wo.child_wait, io_waitid_wait);
    iwa->wo.child_wait.private = req->tctx->task;
    iw->head = &current->signal->wait_chldexit;
    add_wait_queue(iw->head, &iwa->wo.child_wait);

    ret = __do_wait(&iwa->wo);
    if (ret == -ERESTARTSYS) {
        /*
         * If no one grabbed a reference and wakeup hasn't completed,
         * drop the reference and return a skip completion signal.
         */
        if (!io_waitid_drop_issue_ref(req)) {
            io_ring_submit_unlock(ctx, issue_flags);
            return IOU_ISSUE_SKIP_COMPLETE;
        }

        /*
         * Wakeup race occurred, drop the reference and allow the callback to finish.
         */
        io_ring_submit_unlock(ctx, issue_flags);
        return IOU_ISSUE_SKIP_COMPLETE;
    }

    hlist_del_init(&req->hash_node);
    remove_wait_queue(iw->head, &iwa->wo.child_wait);
    ret = io_waitid_finish(req, ret);

    io_ring_submit_unlock(ctx, issue_flags);
done:
    if (ret < 0)
        req_set_fail(req);
    io_req_set_res(req, ret, 0);
    return IOU_OK;
}
