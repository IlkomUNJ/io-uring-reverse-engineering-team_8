// SPDX-License-Identifier: GPL-2.0
/*
 * Contains the core associated with submission side polling of the SQ
 * ring, offloading submissions from the application to a kernel thread.
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/audit.h>
#include <linux/security.h>
#include <linux/cpuset.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "napi.h"
#include "sqpoll.h"

#define IORING_SQPOLL_CAP_ENTRIES_VALUE 8
#define IORING_TW_CAP_ENTRIES_VALUE 8

enum {
    IO_SQ_THREAD_SHOULD_STOP = 0,
    IO_SQ_THREAD_SHOULD_PARK,
};

/*
 * Function: io_sq_thread_unpark
 * Purpose : Unparks the SQ polling thread.
 *           Clears the 'should park' flag, decrements the park_pending counter,
 *           unlocks the mutex, and wakes up the thread waiting on the condition.
 */
void io_sq_thread_unpark(struct io_sq_data *sqd)
    __releases(&sqd->lock)
{
    WARN_ON_ONCE(sqd->thread == current);

    /* Clear the park flag, but if another thread increased park_pending, set it again */
    clear_bit(IO_SQ_THREAD_SHOULD_PARK, &sqd->state);
    if (atomic_dec_return(&sqd->park_pending))
        set_bit(IO_SQ_THREAD_SHOULD_PARK, &sqd->state);
    mutex_unlock(&sqd->lock);
    wake_up(&sqd->wait);
}

/*
 * Function: io_sq_thread_park
 * Purpose : Parks the SQ polling thread.
 *           Increases the park_pending counter, sets the park flag, locks the mutex,
 *           and wakes up the polling thread if necessary.
 */
void io_sq_thread_park(struct io_sq_data *sqd)
    __acquires(&sqd->lock)
{
    WARN_ON_ONCE(data_race(sqd->thread) == current);

    atomic_inc(&sqd->park_pending);
    set_bit(IO_SQ_THREAD_SHOULD_PARK, &sqd->state);
    mutex_lock(&sqd->lock);
    if (sqd->thread)
        wake_up_process(sqd->thread);
}

/*
 * Function: io_sq_thread_stop
 * Purpose : Signals the SQ polling thread to stop and waits for it to exit.
 *           Sets the stop flag, wakes up the thread, and waits for its completion.
 */
void io_sq_thread_stop(struct io_sq_data *sqd)
{
    WARN_ON_ONCE(sqd->thread == current);
    WARN_ON_ONCE(test_bit(IO_SQ_THREAD_SHOULD_STOP, &sqd->state));

    set_bit(IO_SQ_THREAD_SHOULD_STOP, &sqd->state);
    mutex_lock(&sqd->lock);
    if (sqd->thread)
        wake_up_process(sqd->thread);
    mutex_unlock(&sqd->lock);
    wait_for_completion(&sqd->exited);
}

/*
 * Function: io_put_sq_data
 * Purpose : Drops a reference to the SQ data structure and frees it if no references remain.
 *           Stops the SQ polling thread prior to freeing the data.
 */
void io_put_sq_data(struct io_sq_data *sqd)
{
    if (refcount_dec_and_test(&sqd->refs)) {
        WARN_ON_ONCE(atomic_read(&sqd->park_pending));

        io_sq_thread_stop(sqd);
        kfree(sqd);
    }
}

/*
 * Function: io_sqd_update_thread_idle
 * Purpose : Updates the idle timeout for the SQ polling thread.
 *           Iterates over all associated contexts and picks the maximum idle time.
 */
static __cold void io_sqd_update_thread_idle(struct io_sq_data *sqd)
{
    struct io_ring_ctx *ctx;
    unsigned sq_thread_idle = 0;

    list_for_each_entry(ctx, &sqd->ctx_list, sqd_list)
        sq_thread_idle = max(sq_thread_idle, ctx->sq_thread_idle);
    sqd->sq_thread_idle = sq_thread_idle;
}

/*
 * Function: io_sq_thread_finish
 * Purpose : Finalizes the SQ polling thread for a given context.
 *           Parks the thread, removes the context from the thread's list, updates idle timeout,
 *           unparks the thread, and releases the SQ data.
 */
void io_sq_thread_finish(struct io_ring_ctx *ctx)
{
    struct io_sq_data *sqd = ctx->sq_data;

    if (sqd) {
        io_sq_thread_park(sqd);
        list_del_init(&ctx->sqd_list);
        io_sqd_update_thread_idle(sqd);
        io_sq_thread_unpark(sqd);

        io_put_sq_data(sqd);
        ctx->sq_data = NULL;
    }
}

/*
 * Function: io_attach_sq_data
 * Purpose : Attaches the SQ data from an already existing io_uring context (via a file descriptor).
 *           Validates that the current task has permission to use the attached context.
 */
static struct io_sq_data *io_attach_sq_data(struct io_uring_params *p)
{
    struct io_ring_ctx *ctx_attach;
    struct io_sq_data *sqd;
    CLASS(fd, f)(p->wq_fd);

    if (fd_empty(f))
        return ERR_PTR(-ENXIO);
    if (!io_is_uring_fops(fd_file(f)))
        return ERR_PTR(-EINVAL);

    ctx_attach = fd_file(f)->private_data;
    sqd = ctx_attach->sq_data;
    if (!sqd)
        return ERR_PTR(-EINVAL);
    if (sqd->task_tgid != current->tgid)
        return ERR_PTR(-EPERM);

    refcount_inc(&sqd->refs);
    return sqd;
}

/*
 * Function: io_get_sq_data
 * Purpose : Retrieves or allocates the SQ data for the current io_uring instance.
 *           If attach flag is set, attempts to reuse an existing SQ data structure.
 *           Otherwise, allocates a new one.
 */
static struct io_sq_data *io_get_sq_data(struct io_uring_params *p,
                     bool *attached)
{
    struct io_sq_data *sqd;

    *attached = false;
    if (p->flags & IORING_SETUP_ATTACH_WQ) {
        sqd = io_attach_sq_data(p);
        if (!IS_ERR(sqd)) {
            *attached = true;
            return sqd;
        }
        /* fall through for EPERM case, setup new sqd/task */
        if (PTR_ERR(sqd) != -EPERM)
            return sqd;
    }

    sqd = kzalloc(sizeof(*sqd), GFP_KERNEL);
    if (!sqd)
        return ERR_PTR(-ENOMEM);

    atomic_set(&sqd->park_pending, 0);
    refcount_set(&sqd->refs, 1);
    INIT_LIST_HEAD(&sqd->ctx_list);
    mutex_init(&sqd->lock);
    init_waitqueue_head(&sqd->wait);
    init_completion(&sqd->exited);
    return sqd;
}

/*
 * Function: io_sqd_events_pending
 * Purpose : Checks whether there are pending events for the SQ polling thread.
 */
static inline bool io_sqd_events_pending(struct io_sq_data *sqd)
{
    return READ_ONCE(sqd->state);
}

/*
 * Function: __io_sq_thread
 * Purpose : Core submission processing function for the SQ polling thread.
 *           Determines the number of SQ entries to submit (capped for fairness),
 *           optionally overrides credentials, and then submits SQEs while holding the context lock.
 */
static int __io_sq_thread(struct io_ring_ctx *ctx, bool cap_entries)
{
    unsigned int to_submit;
    int ret = 0;

    to_submit = io_sqring_entries(ctx);
    /* Cap submissions if handling multiple rings for fairness */
    if (cap_entries && to_submit > IORING_SQPOLL_CAP_ENTRIES_VALUE)
        to_submit = IORING_SQPOLL_CAP_ENTRIES_VALUE;

    if (to_submit || !wq_list_empty(&ctx->iopoll_list)) {
        const struct cred *creds = NULL;

        if (ctx->sq_creds != current_cred())
            creds = override_creds(ctx->sq_creds);

        mutex_lock(&ctx->uring_lock);
        if (!wq_list_empty(&ctx->iopoll_list))
            io_do_iopoll(ctx, true);

        /*
         * Submit SQEs only if the context is in a valid state (not dying)
         * and if submission is enabled.
         */
        if (to_submit && likely(!percpu_ref_is_dying(&ctx->refs)) &&
            !(ctx->flags & IORING_SETUP_R_DISABLED))
            ret = io_submit_sqes(ctx, to_submit);
        mutex_unlock(&ctx->uring_lock);

        if (to_submit && wq_has_sleeper(&ctx->sqo_sq_wait))
            wake_up(&ctx->sqo_sq_wait);
        if (creds)
            revert_creds(creds);
    }

    return ret;
}

/*
 * Function: io_sq_tw
 * Purpose : Processes task work for the SQ polling thread.
 *           Processes the retry list first, then any new task work, running up to a maximum number of entries.
 *           Returns the total number of task work entries processed.
 */
static unsigned int io_sq_tw(struct llist_node **retry_list, int max_entries)
{
    struct io_uring_task *tctx = current->io_uring;
    unsigned int count = 0;

    if (*retry_list) {
        *retry_list = io_handle_tw_list(*retry_list, &count, max_entries);
        if (count >= max_entries)
            goto out;
        max_entries -= count;
    }
    *retry_list = tctx_task_work_run(tctx, max_entries, &count);
out:
    if (task_work_pending(current))
        task_work_run();
    return count;
}

/*
 * Function: io_sq_tw_pending
 * Purpose : Checks if any task work is still pending either in the retry list or in the task_context.
 */
static bool io_sq_tw_pending(struct llist_node *retry_list)
{
    struct io_uring_task *tctx = current->io_uring;

    return retry_list || !llist_empty(&tctx->task_list);
}

/*
 * Function: io_sq_update_worktime
 * Purpose : Updates the SQ polling thread's recorded work time.
 *           Retrieves the current CPU usage time and adds it to the thread's cumulative work_time.
 */
static void io_sq_update_worktime(struct io_sq_data *sqd, struct rusage *start)
{
    struct rusage end;

    getrusage(current, RUSAGE_SELF, &end);
    end.ru_stime.tv_sec -= start->ru_stime.tv_sec;
    end.ru_stime.tv_usec -= start->ru_stime.tv_usec;

    sqd->work_time += end.ru_stime.tv_usec + end.ru_stime.tv_sec * 1000000;
}

/*
 * Function: io_sq_thread
 * Purpose : Entry point for the SQ polling thread.
 *           Runs the main loop for processing SQ submissions, handling task work,
 *           busy-polling, and scheduling-timeouts.
 */
static int io_sq_thread(void *data)
{
    struct llist_node *retry_list = NULL;
    struct io_sq_data *sqd = data;
    struct io_ring_ctx *ctx;
    struct rusage start;
    unsigned long timeout = 0;
    char buf[TASK_COMM_LEN] = {};
    DEFINE_WAIT(wait);

    /* If the current task has no associated io_uring context, exit immediately */
    if (!current->io_uring) {
        mutex_lock(&sqd->lock);
        sqd->thread = NULL;
        mutex_unlock(&sqd->lock);
        goto err_out;
    }

    snprintf(buf, sizeof(buf), "iou-sqp-%d", sqd->task_pid);
    set_task_comm(current, buf);

    /* Update thread PID and optionally pin the thread to a CPU */
    sqd->task_pid = current->pid;
    if (sqd->sq_cpu != -1) {
        set_cpus_allowed_ptr(current, cpumask_of(sqd->sq_cpu));
    } else {
        set_cpus_allowed_ptr(current, cpu_online_mask);
        sqd->sq_cpu = raw_smp_processor_id();
    }

    /*
     * Force audit context setup in case async operations will trigger audit calls.
     */
    audit_uring_entry(IORING_OP_NOP);
    audit_uring_exit(true, 0);

    mutex_lock(&sqd->lock);
    while (1) {
        bool cap_entries, sqt_spin = false;

        if (io_sqd_events_pending(sqd) || signal_pending(current)) {
            if (io_sqd_handle_event(sqd))
                break;
            timeout = jiffies + sqd->sq_thread_idle;
        }

        /* Determine the submission capacity for fairness if more than one context is attached */
        cap_entries = !list_is_singular(&sqd->ctx_list);
        getrusage(current, RUSAGE_SELF, &start);
        list_for_each_entry(ctx, &sqd->ctx_list, sqd_list) {
            int ret = __io_sq_thread(ctx, cap_entries);

            if (!sqt_spin && (ret > 0 || !wq_list_empty(&ctx->iopoll_list)))
                sqt_spin = true;
        }
        if (io_sq_tw(&retry_list, IORING_TW_CAP_ENTRIES_VALUE))
            sqt_spin = true;

        list_for_each_entry(ctx, &sqd->ctx_list, sqd_list)
            if (io_napi(ctx))
                io_napi_sqpoll_busy_poll(ctx);

        /* Check if we have additional work pending and if the thread should sleep */
        if (sqt_spin || !time_after(jiffies, timeout)) {
            if (sqt_spin) {
                io_sq_update_worktime(sqd, &start);
                timeout = jiffies + sqd->sq_thread_idle;
            }
            if (unlikely(need_resched())) {
                mutex_unlock(&sqd->lock);
                cond_resched();
                mutex_lock(&sqd->lock);
                sqd->sq_cpu = raw_smp_processor_id();
            }
            continue;
        }

        prepare_to_wait(&sqd->wait, &wait, TASK_INTERRUPTIBLE);
        if (!io_sqd_events_pending(sqd) && !io_sq_tw_pending(retry_list)) {
            bool needs_sched = true;

            list_for_each_entry(ctx, &sqd->ctx_list, sqd_list) {
                atomic_or(IORING_SQ_NEED_WAKEUP,
                        &ctx->rings->sq_flags);
                if ((ctx->flags & IORING_SETUP_IOPOLL) &&
                    !wq_list_empty(&ctx->iopoll_list)) {
                    needs_sched = false;
                    break;
                }

                /*
                 * Ensure the store of the wakeup flag is not
                 * reordered with the load of the SQ tail.
                 */
                smp_mb__after_atomic();

                if (io_sqring_entries(ctx)) {
                    needs_sched = false;
                    break;
                }
            }

            if (needs_sched) {
                mutex_unlock(&sqd->lock);
                schedule();
                mutex_lock(&sqd->lock);
                sqd->sq_cpu = raw_smp_processor_id();
            }
            list_for_each_entry(ctx, &sqd->ctx_list, sqd_list)
                atomic_andnot(IORING_SQ_NEED_WAKEUP,
                        &ctx->rings->sq_flags);
        }

        finish_wait(&sqd->wait, &wait);
        timeout = jiffies + sqd->sq_thread_idle;
    }

    if (retry_list)
        io_sq_tw(&retry_list, UINT_MAX);


    /* Cancel any outstanding SQ requests, mark thread as finished,
     * wake up any waiting contexts, run deferred task work, and exit.
     */
    io_uring_cancel_generic(true, sqd);
    sqd->thread = NULL;
    list_for_each_entry(ctx, &sqd->ctx_list, sqd_list)
        atomic_or(IORING_SQ_NEED_WAKEUP, &ctx->rings->sq_flags);
    io_run_task_work();
    mutex_unlock(&sqd->lock);
err_out:
    complete(&sqd->exited);
    do_exit(0);
}

/*
 * Function: io_sqpoll_wait_sq
 * Purpose : Waits for space in the submission queue (SQ) ring.
 *           Repeatedly checks if the SQ ring is not full.
 *           If it is full, the function puts the task to sleep (in TASK_INTERRUPTIBLE)
 *           until space becomes available or a signal is pending.
 */
void io_sqpoll_wait_sq(struct io_ring_ctx *ctx)
{
    DEFINE_WAIT(wait);

    do {
        if (!io_sqring_full(ctx))
            break;
        prepare_to_wait(&ctx->sqo_sq_wait, &wait, TASK_INTERRUPTIBLE);

        if (!io_sqring_full(ctx))
            break;
        schedule();
    } while (!signal_pending(current));

    finish_wait(&ctx->sqo_sq_wait, &wait);
}

/*
 * Function: io_sq_offload_create
 * Purpose : Creates and attaches the submission queue (SQ) polling thread (“SQPOLL”)
 *           for the given io_uring context.
 *           Validates parameters, sets up security checks, allocates and attaches SQ data
 *           (or reuses an existing one if requested via IORING_SETUP_ATTACH_WQ),
 *           configures thread CPU affinity (if specified), creates the SQ thread,
 *           and assigns task context for offloaded submissions.
 */
__cold int io_sq_offload_create(struct io_ring_ctx *ctx,
                struct io_uring_params *p)
{
    struct task_struct *task_to_put = NULL;
    int ret;

    /* Retain compatibility for attach-only attempts */
    if ((ctx->flags & (IORING_SETUP_ATTACH_WQ | IORING_SETUP_SQPOLL)) ==
                IORING_SETUP_ATTACH_WQ) {
        CLASS(fd, f)(p->wq_fd);
        if (fd_empty(f))
            return -ENXIO;
        if (!io_is_uring_fops(fd_file(f)))
            return -EINVAL;
    }
    if (ctx->flags & IORING_SETUP_SQPOLL) {
        struct task_struct *tsk;
        struct io_sq_data *sqd;
        bool attached;

        ret = security_uring_sqpoll();
        if (ret)
            return ret;

        sqd = io_get_sq_data(p, &attached);
        if (IS_ERR(sqd)) {
            ret = PTR_ERR(sqd);
            goto err;
        }

        ctx->sq_creds = get_current_cred();
        ctx->sq_data = sqd;
        ctx->sq_thread_idle = msecs_to_jiffies(p->sq_thread_idle);
        if (!ctx->sq_thread_idle)
            ctx->sq_thread_idle = HZ;

        io_sq_thread_park(sqd);
        list_add(&ctx->sqd_list, &sqd->ctx_list);
        io_sqd_update_thread_idle(sqd);
        /* Do not attach to a dying SQPOLL thread, to avoid races */
        ret = (attached && !sqd->thread) ? -ENXIO : 0;
        io_sq_thread_unpark(sqd);

        if (ret < 0)
            goto err;
        if (attached)
            return 0;

        /* If SQ_AFF is requested, validate and set the desired CPU */
        if (p->flags & IORING_SETUP_SQ_AFF) {
            cpumask_var_t allowed_mask;
            int cpu = p->sq_thread_cpu;

            ret = -EINVAL;
            if (cpu >= nr_cpu_ids || !cpu_online(cpu))
                goto err_sqpoll;
            ret = -ENOMEM;
            if (!alloc_cpumask_var(&allowed_mask, GFP_KERNEL))
                goto err_sqpoll;
            ret = -EINVAL;
            cpuset_cpus_allowed(current, allowed_mask);
            if (!cpumask_test_cpu(cpu, allowed_mask)) {
                free_cpumask_var(allowed_mask);
                goto err_sqpoll;
            }
            free_cpumask_var(allowed_mask);
            sqd->sq_cpu = cpu;
        } else {
            sqd->sq_cpu = -1;
        }

        sqd->task_pid = current->pid;
        sqd->task_tgid = current->tgid;
        tsk = create_io_thread(io_sq_thread, sqd, NUMA_NO_NODE);
        if (IS_ERR(tsk)) {
            ret = PTR_ERR(tsk);
            goto err_sqpoll;
        }

        sqd->thread = tsk;
        task_to_put = get_task_struct(tsk);
        ret = io_uring_alloc_task_context(tsk, ctx);
        wake_up_new_task(tsk);
        if (ret)
            goto err;
    } else if (p->flags & IORING_SETUP_SQ_AFF) {
        /* SQ_AFF cannot be used without SQPOLL */
        ret = -EINVAL;
        goto err;
    }

    if (task_to_put)
        put_task_struct(task_to_put);
    return 0;
err_sqpoll:
    complete(&ctx->sq_data->exited);
err:
    io_sq_thread_finish(ctx);
    if (task_to_put)
        put_task_struct(task_to_put);
    return ret;
}

/*
 * Function: io_sqpoll_wq_cpu_affinity
 * Purpose : Updates the CPU affinity for the SQ polling thread's work queue.
 *           If SQ data exists, parks the SQ thread, sets its CPU affinity using io_wq_cpu_affinity,
 *           and then unparks it. Returns 0 on success or a negative error code.
 */
__cold int io_sqpoll_wq_cpu_affinity(struct io_ring_ctx *ctx,
                     cpumask_var_t mask)
{
    struct io_sq_data *sqd = ctx->sq_data;
    int ret = -EINVAL;

    if (sqd) {
        io_sq_thread_park(sqd);
        /* Do not change affinity for a dying thread */
        if (sqd->thread)
            ret = io_wq_cpu_affinity(sqd->thread->io_uring, mask);
        io_sq_thread_unpark(sqd);
    }

    return ret;
}
