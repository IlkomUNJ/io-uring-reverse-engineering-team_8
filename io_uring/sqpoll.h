// SPDX-License-Identifier: GPL-2.0

/*
 * Structure: io_sq_data
 * Purpose   : Holds data for the submission queue (SQ) polling thread.
 *             - refs: Reference count for the sq data.
 *             - park_pending: Counter for pending park requests.
 *             - lock: Mutex to protect sq data.
 *             - ctx_list: List of io_uring contexts using this sq data.
 *             - thread: Pointer to the SQ polling thread.
 *             - wait: Wait queue for thread synchronization.
 *             - sq_thread_idle: Idle timeout for the SQ polling thread.
 *             - sq_cpu: CPU affinity for the thread (-1 if not set).
 *             - task_pid, task_tgid: PID and TGID of the task that created the thread.
 *             - work_time: Accumulated work time.
 *             - state: SQ data state flags.
 *             - exited: Completion structure to signal thread exit.
 */
struct io_sq_data {
    refcount_t      refs;
    atomic_t        park_pending;
    struct mutex        lock;

    /* ctx's that are using this sqd */
    struct list_head    ctx_list;

    struct task_struct  *thread;
    struct wait_queue_head  wait;

    unsigned        sq_thread_idle;
    int         sq_cpu;
    pid_t           task_pid;
    pid_t           task_tgid;

    u64         work_time;
    unsigned long       state;
    struct completion   exited;
};

/*
 * Function: io_sq_offload_create
 * Purpose : Creates and attaches an SQ polling thread for offloaded submissions.
 */
int io_sq_offload_create(struct io_ring_ctx *ctx, struct io_uring_params *p);

/*
 * Function: io_sq_thread_finish
 * Purpose : Finishes an SQ polling thread for the given context, cleaning up resources.
 */
void io_sq_thread_finish(struct io_ring_ctx *ctx);

/*
 * Function: io_sq_thread_stop
 * Purpose : Signals the SQ polling thread to stop.
 */
void io_sq_thread_stop(struct io_sq_data *sqd);

/*
 * Function: io_sq_thread_park
 * Purpose : Parks the SQ polling thread (i.e. signals it to sleep/wait).
 */
void io_sq_thread_park(struct io_sq_data *sqd);

/*
 * Function: io_sq_thread_unpark
 * Purpose : Unparks (wakes up) the SQ polling thread.
 */
void io_sq_thread_unpark(struct io_sq_data *sqd);

/*
 * Function: io_put_sq_data
 * Purpose : Drops the reference count for the SQ data and frees it if no longer used.
 */
void io_put_sq_data(struct io_sq_data *sqd);

/*
 * Function: io_sqpoll_wait_sq
 * Purpose : Waits for submission queue (SQ) space to become available.
 */
void io_sqpoll_wait_sq(struct io_ring_ctx *ctx);

/*
 * Function: io_sqpoll_wq_cpu_affinity
 * Purpose : Sets the CPU affinity for the SQ polling thread's work queue.
 */
int io_sqpoll_wq_cpu_affinity(struct io_ring_ctx *ctx, cpumask_var_t mask);
