# Task 2: Dependency Injection
For this assigment, we want a little clarity regarding what kind of functions being imported and used on each source. Do note, we record all function actually being used by the source including function defined by itself if actually used inside the file. For the sake of completion, it's better if you straight disregard include list on the source. Instead, trace each function being used to the declared source.

Source | Library | Function utilized | Time Used
-------|--------|--------------| ------------------
alloc_cache.h | /include/linux/kasan.h | kasan_mempool_unpoison_object | 1
| | arch/x86/include/asm/string_64.h| memset | 1
| | alloc_cache.h | io_alloc_cache_get | 1
| | alloc_cache.h | io_cache_alloc_new | 1
| | alloc_cache.h | io_alloc_cache_put | 1
| | linux/mm/slub.c | kfree | 1

Continue with the list untill all functions used in each source are listed.


# c files 

### advise.c

| Source    | Library                  | Function utilized           | Time Used |
|-----------|---------------------------------------------|------------------------------|-----------|
| advise.c  | `fs/advice.c` or `mm/madvise.c`             | `do_madvise`                 | 1         |
|  | `include/linux/sched.h`                     | `current`                    | 1         |
|  | `include/linux/io_uring_types.h`            | `io_kiocb_to_cmd`            | 4         |
| | `include/linux/io_uring_types.h`            | `io_req_set_res`             | 2         |
|   | `include/linux/io_uring_types.h`            | `req_set_fail`               | 1         |
|   | `mm/fadvise.c`                              | `vfs_fadvise`                | 1         |
|   | `arch/x86/include/asm/barrier.h`            | `READ_ONCE`                  | 6         |
|   | `include/linux/kernel.h`                    | `WARN_ON_ONCE`               | 2         |
|   | *advise.c* (internal/self)                  | `io_madvise`                 | 1         |
|  | *advise.c* (internal/self)                  | `io_madvise_prep`            | 1         |
|  | *advise.c* (internal/self)                  | `io_fadvise`                 | 1         |
|  | *advise.c* (internal/self)                  | `io_fadvise_prep`            | 1         |
| | *advise.c* (internal/self)                  | `io_fadvise_force_async`     | 2         |

### alloc_cache.c
| Source         | Library                       | Function utilized         | Time Used |
|----------------|--------------------------------------------------|----------------------------|------------|
|  alloc_cache.c | `mm/util.c` or `include/linux/mm.h`             | `kvfree`                   | 1          |
|                | `mm/util.c` or `include/linux/mm.h`             | `kvmalloc_array`           | 1          |
|                | `mm/slab_common.c` or `include/linux/slab.h`    | `kmalloc`                  | 1          |
|                | `arch/x86/include/asm/string_64.h`              | `memset`                   | 1          |
|                | `include/linux/gfp.h`                           | `GFP_KERNEL`               | 1 (macro)  |
|                | *alloc_cache.c* (internal/self)                 | `io_alloc_cache_get`       | 1          |
|                | *alloc_cache.c* (internal/self)                 | `io_cache_alloc_new`       | 1          |

### cancel.c
| Source     | Library             | Function utilized            | Time Used |
|------------|-----------------------------------------|-------------------------------|-----------|
| cancel.c   | include/linux/io_uring_types.h         | io_kiocb_to_cmd               | 2         |
|            | include/linux/io_uring_types.h         | io_wq_current_is_worker       | 1         |
|            | include/linux/kernel.h                 | WARN_ON_ONCE                  | 1         |
|            | arch/x86/include/asm/barrier.h         | READ_ONCE                     | 4         |
|            | include/linux/spinlock.h               | spin_lock                     | 1         |
|            | include/linux/spinlock.h               | spin_unlock                   | 1         |
|            | include/linux/errno.h                  | -ENOENT                       | 4         |
|            | include/linux/errno.h                  | -EINVAL                       | 3         |
|            | include/linux/errno.h                  | -EALREADY                     | 1         |
|            | include/linux/list.h                   | list_for_each_entry           | 1         |
|            | kernel/io_uring/poll.c                 | io_poll_cancel                | 1         |
|            | kernel/io_uring/waitid.c               | io_waitid_cancel              | 1         |
|            | kernel/io_uring/futex.c                | io_futex_cancel               | 1         |
|            | kernel/io_uring/timeout.c              | io_timeout_cancel             | 1         |
|            | kernel/io_uring/cancel.c (internal)    | io_cancel_req_match           | 2         |
|            | kernel/io_uring/cancel.c (internal)    | io_cancel_cb                  | 1         |
|            | kernel/io_uring/cancel.c (internal)    | io_async_cancel_one           | 2         |
|            | kernel/io_uring/cancel.c (internal)    | io_try_cancel                 | 1         |
|            | kernel/io_uring/cancel.c (internal)    | io_async_cancel_prep          | 1         |
|            | kernel/io_uring/cancel.c (internal)    | __io_async_cancel             | 1         |
|            | kernel/io_uring/cancel.c (internal)    | io_async_cancel               | 1         |
|            | kernel/io_uring/submit.c               | io_ring_submit_lock           | 1         |
|            | kernel/io_uring/submit.c               | io_ring_submit_unlock         | 1         |
|            | kernel/io_uring/workqueue.c            | io_wq_cancel_cb               | 1         |
|            | include/linux/atomic/atomic-instrumented.h | atomic_inc_return        | 1         |

### epoll.c
| Source        | Library / Source Origin                    | Function utilized           | Time Used |
|---------------|---------------------------------------------|-----------------------------|-----------|
| epoll.c       | include/linux/kernel.h                     | READ_ONCE                  | 4         |
| e      | include/linux/errno.h                      | -                           | 0         |
|     | include/linux/file.h                       | -                           | 0         |
|      | include/linux/fs.h                         | -                           | 0         |
|      | include/linux/uaccess.h                    | copy_from_user              | 1         |
|       | include/linux/io_uring.h                   | io_kiocb_to_cmd             | 4         |
|       | include/linux/io_uring.h                   | io_req_set_res              | 2         |
|       | include/linux/io_uring.h                   | req_set_fail                | 2         |
|        | include/linux/eventpoll.h                  | epoll_sendevents            | 1         |
|      | fs/io_uring.c                              | do_epoll_ctl                | 1         |
|        | fs/io_uring.c                              | ep_op_has_event             | 1         |
|       | fs/io_uring.c                              | io_epoll_ctl_prep           | 1         |
|        | fs/io_uring.c                              | io_epoll_ctl                | 1         |
|       | fs/io_uring.c                              | io_epoll_wait_prep          | 1         |
|       | fs/io_uring.c                              | io_epoll_wait               | 1         |

### eventfd.c
Source | Library | Function utilized | Time Used |
-------|---------|-------------------|------------------|
eventfd.c | /linux/kernel.h | pr_warn | 1 |
| /linux/errno.h | -EBUSY | 1 |
| /linux/errno.h | -EFAULT | 1 |
| /linux/mm.h | kmalloc | 1 |
| /linux/slab.h | kfree | 1 |
| /linux/slab.h | GFP_KERNEL | 1 |
| /linux/eventfd.h | eventfd_ctx_fdget | 1 |
| /linux/eventfd.h | eventfd_signal_mask | 1 |
| /linux/eventfd.h | eventfd_ctx_put | 1 |
| /linux/eventfd.h | eventfd_signal_allowed | 1 |
| /linux/eventfd.h | eventfd_signal_mask | 1 |
| /linux/eventpoll.h | EPOLL_URING_WAKE | 1 |
| /linux/io_uring.h | io_wq_current_is_worker | 1 |
| /linux/io_uring_types.h | IORING_CQ_EVENTFD_DISABLED | 1 |
| io-wq.h | io_eventfd_free | 1 |
| io-wq.h | io_eventfd_put | 1 |
| io-wq.h | io_eventfd_do_signal | 1 |
| io-wq.h | io_eventfd_signal | 1 |
| io-wq.h | io_eventfd_flush_signal | 1 |
| io-wq.h | io_eventfd_register | 1 |
| io-wq.h | io_eventfd_unregister | 1 |

### fdinfo.c
| Source    | Library                             | Function utilized                  | Time Used |
|-----------|-------------------------------------|------------------------------------|-----------|
| fdinfo.c  | linux/kernel.h                      | min                                | 1         |
|           | linux/seq_file.h                    | seq_file                           | 1         |
|           | linux/seq_file.h                    | seq_printf                         | 6+        |
|           | linux/seq_file.h                    | seq_puts                           | 5+        |
|           | linux/seq_file.h                    | seq_put_decimal_ull                | 9+        |
|           | linux/seq_file.h                    | seq_putc                           | 1         |
|           | linux/seq_file.h                    | seq_put_hex_ll                     | 1         |
|           | linux/fs.h                          | struct file                        | 1         |
|           | linux/fs.h                          | file->private_data                 | 1         |
|           | linux/uaccess.h / io_uring.h        | READ_ONCE                          | 6+        |
|           | linux/sched.h / sys/resource.h      | getrusage                          | 1         |
|           | linux/mutex.h                       | mutex_trylock                      | 1         |
|           | io_uring.h                          | io_ring_ctx                        | 1         |
|           | io_uring.h                          | io_uring_get_opcode                | 1         |
|           | linux/cred.h                        | from_kuid_munged                   | 4         |
|           | linux/cred.h                        | from_kgid_munged                   | 5         |
|           | linux/cred.h                        | struct cred                        | 1         |
|           | linux/user_namespace.h              | seq_user_ns                        | 1         |
|           | io_uring.h                          | IORING_SETUP_CQE32                 | 1         |
|           | io_uring.h                          | IORING_SETUP_SQE128                | 1         |
|           | io_uring.h                          | IORING_SETUP_NO_SQARRAY            | 1         |
|           | io_uring.h                          | IORING_SETUP_SQPOLL                | 1         |
|           | io_uring.h                          | IO_URING_NAPI_TRACKING_* constants | 3         |
|           | fdinfo.c (itself)                   | io_uring_show_cred                 | 1         |
|           | fdinfo.c (itself)                   | common_tracking_show_fdinfo        | 2         |
|           | fdinfo.c (itself)                   | napi_show_fdinfo                   | 1         |

### filetable.c
| Source       | Library                                     | Function utilized                  | Time Used |
|--------------|---------------------------------------------|------------------------------------|-----------|
| filetable.c  | linux/find_bit.h                            | find_next_zero_bit                 | 1         |
|              | linux/bitmap.h                              | bitmap_zalloc                      | 1         |
|              | linux/bitmap.h                              | bitmap_free                        | 1         |
|              | linux/slab.h                                | GFP_KERNEL_ACCOUNT (flag)          | 1         |
|              | linux/file.h                                | fput                               | 1         |
|              | linux/uaccess.h                             | copy_from_user                     | 1         |
|              | linux/overflow.h                            | check_add_overflow                 | 1         |
|              | linux/io_uring.h                            | io_is_uring_fops                   | 1         |
|              | io_uring.h                                  | io_ring_submit_lock                | 1         |
|              | io_uring.h                                  | io_ring_submit_unlock              | 1         |
|              | rsrc.h                                      | io_rsrc_data_alloc                 | 1         |
|              | rsrc.h                                      | io_rsrc_data_free                  | 2         |
|              | rsrc.h                                      | io_rsrc_node_alloc                 | 1         |
|              | rsrc.h                                      | io_rsrc_node_lookup                | 1         |
|              | rsrc.h                                      | io_reset_rsrc_node                 | 2         |
|              | filetable.h                                 | io_file_bitmap_get                 | 1         |
|              | filetable.h                                 | io_file_bitmap_set                 | 1         |
|              | filetable.h                                 | io_file_bitmap_clear               | 1         |
|              | filetable.h                                 | io_file_table_set_alloc_range      | 1         |
|              | filetable.c (itself)                        | io_install_fixed_file              | 1         |
|              | filetable.c (itself)                        | __io_fixed_fd_install              | 1         |
|              | filetable.c (itself)                        | io_fixed_fd_install                | 1         |
|              | filetable.c (itself)                        | io_fixed_fd_remove                 | 1         |
|              | filetable.c (itself)                        | io_alloc_file_tables               | 1         |
|              | filetable.c (itself)                        | io_free_file_tables                | 1         |
|              | filetable.c (itself)                        | io_register_file_alloc_range       | 1         |
|              | filetable.c (itself)                        | io_fixed_file_set                  | 1         |


### fs.c
Source | Library | Function utilized | Time Used |
-------|---------|-------------------|-----------|
fs.c | linux/fs.h | do_renameat2 | 1 |
| linux/fs.h | do_rmdir | 1 |
 | linux/fs.h | do_unlinkat | 1 |
 | linux/fs.h | do_mkdirat | 1 |
 | linux/fs.h | do_symlinkat | 1 |
 | linux/fs.h | do_linkat | 1 |
 | linux/fs/namei.h | getname | 5 |
 | linux/fs/namei.h | getname_uflags | 1 |
 | linux/fs/namei.h | putname | 6 |
 | linux/kernel.h | WARN_ON_ONCE | 5 |
| linux/io_uring.h | io_kiocb_to_cmd | 12 |
 | linux/io_uring.h | io_req_set_res | 5 |
 | linux/io_uring.h | REQ_F_NEED_CLEANUP | 10 |
 | linux/io_uring.h | REQ_F_FORCE_ASYNC | 10 |
 | linux/io_uring.h | REQ_F_FIXED_FILE | 5 |
 | linux/io_uring.h | IO_URING_F_NONBLOCK | 5 |
 | linux/io_uring.h | IOU_OK | 5 |
 | linux/uaccess.h | u64_to_user_ptr | 6 |
 | linux/compiler.h | unlikely | 6 |
 | linux/compiler.h | READ_ONCE | 18 |
 | linux/err.h | IS_ERR | 8 |
| linux/err.h | PTR_ERR | 7 |

### futex.c
Source | Library | Function utilized | Time Used |
-------|--------|--------------------|------------|
futex.c | alloc_cache.h | io_alloc_cache_init | 1 |
| alloc_cache.h | io_alloc_cache_free | 1 |
| alloc_cache.h | io_cache_free | 1 |
| alloc_cache.h | io_alloc_cache_free | 1 |
| futex.h | io_kiocb_to_cmd | 3 |
| futex.h | futex_unqueue_multiple | 1 |
| futex.h | futex_unqueue | 1 |
| futex.h | futex2_to_flags | 1 |
| futex.h | futex_flags_valid | 1 |
| futex.h | futex_validate_input | 2 |
| futex.h | futex_parse_waitv | 1 |
| futex.h | __futex_wake_mark | 2 |
| futex.h | futex_wait_multiple_setup | 1 |
| io_uring.h | io_req_task_complete | 1 |
| io_uring.h | io_req_set_res | 3 |
| io_uring.h | io_req_task_work_add | 3 |
| io_uring.h | io_ring_submit_lock | 1 |
| io_uring.h | io_ring_submit_unlock | 1 |
| io_uring.h | io_cancel_remove | 1 |
| io_uring.h | io_cancel_remove_all | 1 |
| io_uring.h | req_set_fail | 1 |
| linux/mm/slub.c | kfree | 3 |
| linux/slab.h | kcalloc | 1 |
| linux/uaccess.h | u64_to_user_ptr | 2 |
| asm-generic/bitops/instrumented-atomic.h | test_bit | 1 |
| asm-generic/bitops/instrumented-atomic.h | test_and_set_bit_lock | 1 |
| linux/kernel.h | unlikely | 5 |
| linux/fs.h | struct file | 1 |

### io_uring.c
Source | Library | Function utilized | Time Used |
-------|--------|--------------| ------------------|
io_uring.c | linux/kernel.h | WARN_ON_ONCE | 16 |
| | linux/init.h | __cold | 30 |
| | linux/errno.h | -ECANCELED | 1 |
| | linux/syscalls.h | SYSCALL_DEFINE2 | 1 |
| | net/compat.h | compat_ptr | 1 |
| | linux/refcount.h | refcount_add | 1 |
| | linux/uio.h | iov_iter_count | 1 |
| | linux/bits.h | set_bit | 2 |
| | linux/bits.h | clear_bit | 2 |
| | linux/sched/signal.h | current | 35+- |
| | linux/fs.h | file_inode | 3 |
| | linux/fs.h | f_inode | 1 |
| | linux/fs.h | O_DIRECT | Multiple |
| | linux/file.h | f_op | Multiple |
| | linux/file.h | fop_flags | Multiple |
| | linux/mm.h | kvmalloc_array | 1 |
| | linux/mm.h | kvfree | Multiple |
| | linux/mm.h | GFP_KERNEL | Multiple |
| | linux/mm.h | __GFP_NOWARN | Multiple |
| | linux/mm.h | __GFP_ACCOUNT | Multiple |
| | linux/mman.h | VM_UFFD_MISSING | 1 |
| | linux/percpu.h | percpu_ref_init | 1 |
| | linux/percpu.h | percpu_ref_get | Multiple |
| | linux/percpu.h | percpu_ref_get_many | 1 |
| | linux/percpu.h | percpu_ref_put | Multiple |
| | linux/percpu.h | percpu_ref_exit | 1 |
| | linux/percpu.h | percpu_counter_add | 1 |
| | linux/percpu.h | percpu_counter_sub | 2 |
| | linux/slab.h | kzalloc | 1 |
| | linux/slab.h | kfree | Multiple |
| | linux/slab.h | kmem_cache_alloc | 1 |
| | linux/slab.h | kmem_cache_alloc_bulk | 1 |
| | linux/slab.h | kmem_cache_free | 1 |
| | linux/bvec.h | bio_iov_iter | 1 |
| | linux/net.h | sock_kern_write | 1 |
| | net/sock.h | sock_alloc_send_skb | 1 |
| | linux/anon_inodes.h | anon_inode_getfd | 1 |
| | linux/sched/mm.h | get_task_mm | 1 |
| | linux/sched/mm.h | mmput | 1 |
| | linux/uaccess.h | copy_from_user | Multiple |
| | linux/uaccess.h | copy_to_user | Multiple |
| | linux/nospec.h | array_index_nospec | 1 |
| | linux/fsnotify.h | fsnotify_add_inode_queue | 1 |
| | linux/fadvise.h | fadvise_fadvise | 1 |
| | linux/task_work.h | INIT_DELAYED_WORK | 1 |
| | linux/task_work.h | io_req_task_work_add | Multiple |
| | linux/task_work.h | llist_del_all | 1 |
| | linux/task_work.h | llist_for_each_entry_safe | 1 |
| | linux/io_uring.h | io_kiocb | Multiple |
| | linux/io_uring.h | io_uring_params | 1 |
| | linux/io_uring.h | IORING_SETUP_SQPOLL | 1 |
| | linux/io_uring.h | IORING_SETUP_CQE32 | Multiple |
| | linux/io_uring.h | IORING_SETUP_TASKRUN_FLAG | Multiple |
| | linux/io_uring.h | IORING_SQ_NEED_WAKEUP | 1 |
| | linux/io_uring.h | IORING_SQ_CQ_OVERFLOW | Multiple |
| | linux/io_uring.h | IOSQE_FIXED_FILE | 1 |
| | linux/io_uring.h | IOSQE_IO_LINK | 1 |
| | linux/io_uring.h | IOSQE_IO_HARDLINK | 1 |
| | linux/io_uring.h | IOSQE_ASYNC | 1 |
| | linux/io_uring.h | IOSQE_BUFFER_SELECT | 1 |
| | linux/io_uring.h | IOSQE_IO_DRAIN | 1 |
| | linux/io_uring.h | IOSQE_CQE_SKIP_SUCCESS | 1 |
| | linux/io_uring.h | io_uring_cqe | Multiple |
| | linux/io_uring.h | io_uring_sqe | 1 |
| | linux/io_uring.h | io_uring_task | Multiple |
| | linux/io_uring.h | io_rings | Multiple |
| | linux/io_uring.h | io_submit_state | Multiple |
| | linux/io_uring.h | IO_URING_F_IOWQ | 1 |
| | linux/io_uring.h | IO_URING_F_COMPLETE_DEFER | 1 |
| | linux/io_uring.h | IO_URING_F_MULTISHOT | 1 |
| | linux/io_uring/cmd.h | io_cold_defs | Multiple |
| | linux/audit.h | audit_get_loginuid | 1 |
| | linux/security.h | security_file_permission | 1 |
| | linux/jump_label.h | static_key_false | 1 |
| | asm/shmparam.h | SHMLBA | 1 |
| | trace/events/io_uring.h | trace_io_uring_queue_async_work | 1 |
| | trace/events/io_uring.h | trace_io_uring_complete | 1 |
| | trace/events/io_uring.h | trace_io_uring_cqe_overflow | 1 |
| | uapi/linux/io_uring.h | IORING_OP_URING_CMD | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_SETUP | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_REGISTER | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_UNREGISTER | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_SQPOLL_CREATE | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_SQPOLL_REMOVE | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_GET_SQD_PREF | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_FENCE | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_NOP | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_POLL_ADD | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_POLL_REMOVE | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_URING_FD_CREATE | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_URING_FD_RELEASE | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_ রেজিস্টার_ ফাইল_RANGE | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_UNREGISTER_FILE_RANGE | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_ রেজিস্টার_BUFFERS | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_UNREGISTER_BUFFERS | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_ রেজিস্টার_FILES | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_UNREGISTER_FILES | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_ রেজিস্টার_EVENTFD | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_UNREGISTER_EVENTFD | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_ রেজিস্টার_EVENTFD_ASYNC | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_ রেজিস্টার_PROBE | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_ রেজিস্টার_PERSONALITY | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_UNREGISTER_PERSONALITY | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_ রেজিস্টার_RESTRICTIONS | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_ENABLE_URING_DEBUG | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_ রেজিস্টার_IOWQ_MAX_WORKERS | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_ রেজিস্টার_FILES_UPDATE | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_ রেজিস্টার_BUFFERS_UPDATE | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_ রেজিস্টার_PBUF | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_UNREGISTER_PBUF | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_PBUF_RING_CREATE | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_PBUF_RING_REMOVE | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_ রেজিস্টার_SYNC_FD | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_UNREGISTER_SYNC_FD | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_ রেজিস্টার_IORING_MEM | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_UNREGISTER_IORING_MEM | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_ রেজিস্টার_KERNEL_RANGE | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_ UNREGISTER_KERNEL_RANGE | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_SETUP_ADD | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_SETUP_REMOVE | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_SETUP_GET_FEATURES | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_ রেজিস্টার_MEMORY_MAPPING | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_UNREGISTER_MEMORY_MAPPING | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_SQ_AFFINITY | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_CQ_AFFINITY | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_TASK_REG | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_TASK_UNREG | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_EXT_OP_REGISTER | 1 |
| | uapi/linux/io_uring.h | IORING_URING_CMD_EXT_OP_UNREGISTER | 1 |
| | io-wq.h | io_wq_hash_work | 1 |
| | io-wq.h | io_wq_enqueue | 1 |
| | io-wq.h | io_wq_is_hashed | 1 |
| | io_uring.h | io_ring_ctx | Multiple |
| | io_uring.h | io_issue_defs | Multiple |
| | io_uring.h | io_cold_def | Multiple |
| | io_uring.h | io_alloc_cache_init | Multiple |
| | io_uring.h | io_alloc_cache_free | Multiple |
| | io_uring.h | io_get_cqe | Multiple |
| | io_uring.h | io_get_cqe_overflow | 1 |
| | io_uring.h | io_cqring_wake | Multiple |
| | io_uring.h | io_submit_flush_completions | Multiple |
| | io_uring.h | io_req_task_complete | Multiple |
| | io_uring.h | io_req_task_queue | Multiple |
| | io_uring.h | io_req_task_queue_fail | 1 |
| | io_uring.h | io_req_set_res | Multiple |
| | io_uring.h | io_put_kbuf | 1 |
| | io_uring.h | io_req_complete_defer | 1 |
| | io_uring.h | req_set_fail | Multiple |
| | io_uring.h | io_file_get_flags | 1 |
| | io_uring.h | io_req_set_refcount | 1 |
| | io_uring.h | __io_req_set_refcount | 1 |
| | io_uring.h | io_queue_linked_timeout | Multiple |
| | io_uring.h | io_disarm_next | Multiple |
| | io_uring.h | req_ref_put | 1 |
| | io_uring.h | io_napi_init | 1 |
| | opdef.h |  |  |
| | refs.h | io_req_add_to_cache | 1 |
| | refs.h | io_req_track_inflight | Multiple |
| | refs.h | req_ref_get | 1 |
| | refs.h | io_put_task | 1 |
| | tctx.h | io_uring_task_alloc | 1 |
| | tctx.h | io_uring_task_free | 1 |
| | tctx.h | io_uring_drop_tctx_refs | 1 |
| | register.h | io_register_files_update | 1 |
| | register.h | io_unregister_files | 1 |
| | register.h | io_register_buffers_update | 1 |
| | register.h | io_unregister_buffers | 1 |
| | register.h | io_register_eventfd | 1 |
| | register.h | io_unregister_eventfd | 1 |
| | register.h | io_register_restrictions | 1 |
| | register.h | io_register_iowq_max_workers | 1 |
| | register.h | io_register_memory_mapping | 1 |
| | register.h | io_unregister_memory_mapping | 1 |
| | sqpoll.h | io_sqpoll_create | 1 |
| | sqpoll.h | io_sqpoll_remove | 1 |
| | sqpoll.h | io_sqpoll_get_sqd_pref | 1 |
| | fdinfo.h | io_show_fdinfo | 1 |
| | kbuf.h | io_kbuf_drop_legacy | 1 |
| | rsrc.h | io_rsrc_cache_init | 1 |
| | rsrc.h | io_rsrc_cache_free | 1
| | rsrc.h | io_register_rsrc | 1 |
| | rsrc.h | io_unregister_rsrc | 1 |
| | cancel.h | io_cancel_generic | 1 |
| | cancel.h | io_try_cancel_all | 1 |
| | net.h | io_net_register | 1 |
| | net.h | io_net_unregister | 1 |
| | notif.h | io_notif_register | 1 |
| | notif.h | io_notif_unregister | 1 |
| | waitid.h | io_waitid_register | 1 |
| | waitid.h | io_waitid_unregister | 1 |
| | futex.h | io_futex_cache_init | 1 |
| | futex.h | io_futex_cache_free | 1 |
| | futex.h | io_futex_register | 1 |
| | futex.h | io_futex_unregister | 1 |
| | napi.h | io_napi_add_vector | 1 |
| | napi.h | io_napi_del_vector | 1 |
| | uring_cmd.h | io_uring_cmd | 1 |
| | msg_ring.h | io_msg_ring_register | 1 |
| | msg_ring.h | io_msg_ring_unregister | 1 |
| | memmap.h | io_mem_register | 1 |
| | memmap.h | io_mem_unregister | 1 |
| | zcrx.h | io_zcrx_register | 1 |
| | zcrx.h | io_zcrx_unregister | 1 |
| | timeout.h | io_queue_timeout | 1 |
| | timeout.h | io_del_timer | 1 |
| | timeout.h | io_arm_timer | 1 |
| | timeout.h | io_flush_timeouts | 1 |
| | poll.h | io_poll_add | 1 |
| | poll.h | io_poll_remove | 1 |
| | rw.h | io_rw_cache_free | 1 |
| | rw.h | io_rw_register | 1 |
| | rw.h | io_rw_unregister | 1 |
| | alloc_cache.h | io_alloc_cache_free | 4 |
| | eventfd.h | io_eventfd_register | 1 |
| | eventfd.h | io_eventfd_unregister | 1 |
| | eventfd.h | io_eventfd_flush_signal | 1 |
etc.

### io-wq.c
Source | Library | Function utilized | Time Used
-------|--------|--------------| ------------------
io-wq.c | linux/kernel.h | WARN_ON_ONCE | 3
| | linux/init.h | subsys_initcall | 1
| | linux/errno.h | -EINVAL | 4
| | linux/errno.h | -ENOMEM | 2
| | linux/sched/signal.h | /* (No functions used) */ | 0
| | linux/percpu.h | /* /* (No functions used) */*/ | 0
| | linux/slab.h | kzalloc | 2
| | linux/slab.h | kfree | 1
| | linux/rculist_nulls.h | /* /* (No functions used) */ */ | 0
| | linux/cpu.h | /* /* (No functions used) */*/ | 0
| | linux/cpuset.h | cpuset_cpus_allowed | 2
| | linux/task_work.h | /* /* (No functions used) */| 0
| | linux/audit.h | /*/* (No functions used) */ */ | 0
| | linux/mmu_context.h | /* /* (No functions used) */ */ | 0
| | uapi/linux/io_uring.h | /* /* (No functions used) */ */ | 0
| | io-wq.h | IO_WQ_BOUND | 1
| | io-wq.h | IO_WQ_UNBOUND | 1
| | io-wq.h | INIT_WQ_LIST | 1
| | slist.h | /* /* (No functions used) */ */ | 0
| | io_uring.h | /* /* (No functions used) */*/ | 0
| | linux/kernel.h | container_of | 1
| | linux/kernel.h | test_bit | 1
| | linux/kernel.h | set_bit | 1
| | linux/kernel.h | clear_bit | 1
| | linux/kernel.h | BUILD_BUG_ON | 3
| | linux/errno.h | ERR_PTR | 3
| | linux/errno.h | raw_spin_lock | 2
| | linux/errno.h | raw_spin_unlock | 2
| | linux/errno.h | atomic_set | 2
| | linux/errno.h | test_and_clear_bit | 1
| | linux/errno.h | rcu_read_lock | 3
| | linux/errno.h | rcu_read_unlock | 3
| | linux/errno.h | list_del_init | 1
| | linux/errno.h | get_task_struct | 1
| | linux/errno.h | init_completion | 1
| | linux/errno.h | wait_for_completion | 1
| | linux/errno.h | spin_lock_irq | 2
| | linux/errno.h | spin_unlock_irq | 2
| | linux/errno.h | alloc_cpumask_var | 2
| | linux/errno.h | free_cpumask_var | 2
| | linux/errno.h | task_rlimit | 2
| | linux/errno.h | INIT_LIST_HEAD | 1
| | linux/errno.h | INIT_HLIST_NULLS_HEAD | 1
| | linux/errno.h | cpuhp_state_add_instance_nocalls | 1
| | linux/errno.h | io_wq_put_hash | 2
| | linux/errno.h | task_work_cancel_match | 1
| | linux/errno.h | put_task_struct | 1
| | linux/errno.h | cpuhp_state_remove_instance_nocalls | 1
| | linux/errno.h | cpumask_subset | 1
| | linux/errno.h | cpumask_copy | 2
| | linux/errno.h | max_t | 1
| | linux/errno.h | cpuhp_setup_state_multi | 1
| | linux/errno.h | hlist_entry_safe | 1

### kbuf.c
Source | Library | Function utilized | Time Used |
-------|--------|-------------------|------------|
kbuf.c | linux/kernel.h | likely, unlikely | 2 |
| linux/errno.h | -ENOBUFS, -ENOMEM | 2 |
| linux/fs.h | struct file | 1 |
| linux/file.h | io_file_can_poll | 1 |
| linux/mm.h | UIO_MAXIOV | 1 |
| linux/slab.h | kmalloc_array, kfree | 2 |
| linux/namei.h | - | 0 |
| linux/poll.h | - | 0 |
| linux/vmalloc.h | - | 0 |
| linux/io_uring.h | struct io_kiocb, struct io_ring_ctx, REQ_F_*, IO_URING_F_UNLOCKED, etc. | 1 |
| uapi/linux/io_uring.h | struct io_uring_buf, struct io_uring_buf_ring | 1 |
| io_uring.h | io_ring_submit_lock, io_ring_submit_unlock, io_file_can_poll, etc. | 3 |
| opdef.h | IOBL_INC, IOBL_BUF_RING, etc. | 1 |
| kbuf.h | io_kbuf_commit, io_buffer_select, etc. | 2 |
| memmap.h | xa_load, xa_store, xa_err | 3 |
| linux/types.h | __u32, __u64, __u16, size_t | 1 |
| asm-generic/int-ll64.h | INT_MAX | 1 |
| asm/barrier.h | smp_load_acquire | 1 |
| asm/uaccess.h | u64_to_user_ptr | 2 |
| linux/list.h | list_empty, list_first_entry, list_del, list_add | 4 |
| linux/xarray.h | xa_load, xa_store, xa_err | 3 |
| linux/mutex.h | guard (mutex) | 1 |
| linux/lockdep.h | lockdep_assert_held | 1 |
| linux/string.h | min_t, min_not_zero | 2 |


### memmap.c
Source | Library | Function utilized | Time Used
-------|--------|-------------------|------------------
memmap.c | /linux/kernel.h | printk | 1
| | /linux/init.h | __init | 1
| | /linux/errno.h | -ENOMEM | 2
| | /linux/mm.h | alloc_pages | 2
| | /linux/mman.h | mmap | 1
| | /linux/slab.h | kvmalloc_array | 1
| | /linux/vmalloc.h | vmap | 2
| | /linux/io_uring.h | - | 3
| | /linux/io_uring_types.h | - | 2
| | /asm/shmparam.h | - | 1
|  | memmap.h | io_mem_alloc_compound | 1
| | memmap.h | io_pin_pages | 1
|  | memmap.h | io_free_region | 2
|  | memmap.h | io_region_init_ptr | 1
| | memmap.h | io_region_pin_pages | 1
|  | memmap.h | io_region_allocate_pages | 1
|  | memmap.h | io_create_region | 1
|  | memmap.h | io_create_region_mmap_safe | 1
| | memmap.h | io_mmap_get_region | 1
| | memmap.h | io_region_validate_mmap | 1
|  | memmap.h | io_uring_validate_mmap_request | 1
| | memmap.h | io_region_mmap | 1
| | memmap.h | io_uring_mmap | 1
|  | memmap.h | io_uring_get_unmapped_area | 1

### msg_ring.c
Source | Library | Function utilized | Time Used
-------|--------|-------------------|------------------
msg_ring.c | /linux/kernel.h | printk | 1
| | /linux/errno.h | - | 1
| | /linux/file.h | fput | 1
| | /linux/slab.h | kmem_cache_alloc | 2
| | /linux/slab.h | kmem_cache_free | 2
| | /linux/nospec.h | - | 1
| | /linux/io_uring.h | io_req_task_work_add_remote | 1
| | /linux/io_uring.h | io_add_aux_cqe | 1
| | /linux/io_uring.h | io_post_aux_cqe | 3
| | /linux/io_uring.h | io_req_set_res | 2
| | /linux/io_uring.h | io_req_task_work_add | 1
| | /linux/io_uring.h | io_slot_file | 1
| | /linux/io_uring.h | io_rsrc_node_lookup | 1
| | /linux/io_uring.h | io_ring_submit_lock | 1
| | /linux/io_uring.h | io_ring_submit_unlock | 1
| | /linux/io_uring.h | io_kiocb_to_cmd | 2
| | /linux/io_uring.h | io_is_uring_fops | 1
| | /linux/io_uring.h | io_req_queue_tw_complete | 1
| | /linux/io_uring.h | io_double_unlock_ctx | 1
| | /linux/io_uring.h | io_lock_external_ctx | 2
| | /linux/io_uring.h | init_task_work | 1
| | /linux/io_uring.h | task_work_add | 1
| | /linux/io_uring.h | get_file | 1
| | /linux/io_uring.h | io_alloc_cache_get | 1
| | /linux/io_uring.h | io_alloc_cache_put | 1
| | /linux/io_uring.h | io_uring_fops | 1
| | /linux/io_uring.h | percpu_ref_get | 2
| | /linux/io_uring.h | percpu_ref_put | 1

### napi.c
Source | Library | Function utilized | Time Used
-------|--------|-------------------|------------------
napi.c | io_uring.h | napi_busy_loop_rcu | 2
| | io_uring.h | io_should_wake | 1
| | io_uring.h | io_has_work | 1
| | io_uring.h | busy_loop_current_time | 1
| | io_uring.h | signal_pending | 1
| | io_uring.h | io_napi_add_id | 1
| | io_uring.h | io_napi_del_id | 1
| | io_uring.h | io_napi_remove_stale | 1
| | io_uring.h | io_napi_busy_loop_timeout | 1
| | io_uring.h | net_to_ktime | 1
| | io_uring.h | ktime_add | 1
| | io_uring.h | ktime_sub | 1
| | io_uring.h | ktime_to_us | 1
| | io_uring.h | copy_from_user | 1
| | io_uring.h | copy_to_user | 1
| | io_uring.h | list_is_singular | 1
| | io_uring.h | INIT_LIST_HEAD | 1
| | io_uring.h | list_for_each_entry_rcu | 3
| | io_uring.h | hash_min | 1
| | io_uring.h | WRITE_ONCE | 2
| | io_uring.h | kmalloc | 1
| | io_uring.h | kfree | 1
| | io_uring.h | kfree_rcu | 1
| | io_uring.h | hash_del_rcu | 1
| | io_uring.h | list_del_rcu | 1
| | io_uring.h | list_add_tail_rcu | 1
| | io_uring.h | hlist_add_tail_rcu | 1
| | io_uring.h | spin_lock_init | 1
| | io_uring.h | spin_lock | 1
| | io_uring.h | spin_unlock | 1
| | io_uring.h | scoped_guard | 2
| | io_uring.h | guard | 2
| | io_uring.h | time_after | 1
| | io_uring.h | READ_ONCE | 2
| | io_uring.h | __user | 1
| | io_uring.h | napi_id_valid | 1
| | io_uring.h | ns_to_ktime | 1

### net.c
Source | Library | Function utilized | Time Used
-------|--------|--------------| ------------------
net.c | linux/kernel.h | WARN_ON_ONCE | 3
| | linux/errno.h | -EINVAL | 13
| | linux/errno.h | -ENOTSOCK | 8
| | linux/errno.h | -EFAULT | 1
| | linux/errno.h | -ENOMEM | 3
| | linux/errno.h | -EAGAIN | 10
| | linux/errno.h | -EINTR | 5
| | linux/errno.h | -ERESTARTSYS | 5
| | linux/errno.h | IOU_REQUEUE | 2
| | linux/errno.h | -EOPNOTSUPP | 2
| | linux/errno.h | -EBADFD | 1
| | linux/errno.h | -EISCONN | 1
| | linux/errno.h | -ECONNRESET | 1
| | linux/file.h | sock_from_file | 7
| | linux/slab.h | unlikely | 20
| | linux/slab.h | kfree | 1
| | linux/net.h | io_zcrx_recv | 1
| | linux/net.h | __sys_shutdown_sock | 1
| | linux/net.h | sock_sendmsg | 2
| | linux/net.h | __sys_sendmsg_sock | 2
| | linux/net.h | test_bit | 2
| | linux/net.h | __sys_connect_file | 1
| | linux/net.h | sock_error | 1
| | linux/net.h | __sys_bind_socket | 1
| | linux/net.h | __sys_listen_socket | 1
| | net/compat.h | io_is_compat | 3
| | linux/io_uring.h | io_kiocb_to_cmd | 11
| | linux/io_uring.h | READ_ONCE | 20
| | linux/io_uring.h | io_req_set_res | 9
| | linux/io_uring.h | IOU_COMPLETE | 4
| | linux/io_uring.h | REQ_F_APOLL_MULTISHOT | 2
| | linux/io_uring.h | IOU_RETRY | 4
| | linux/io_uring.h | io_notif_flush | 2
| | linux/io_uring.h | io_alloc_notif | 1
| | linux/io_uring.h | IORING_CQE_F_NOTIF | 1
| | linux/io_uring.h | REQ_F_NEED_CLEANUP | 3
| | linux/io_uring.h | REQ_F_POLL_NO_LAZY | 1
| | linux/io_uring.h | IORING_SEND_ZC_REPORT_USAGE | 1
| | linux/io_uring.h | io_notif_to_data | 2
| | linux/io_uring.h | MSG_NOSIGNAL | 2
| | linux/io_uring.h | MSG_ZEROCOPY | 1
| | linux/io_uring.h | MSG_DONTWAIT | 4
| | linux/io_uring.h | REQ_F_IMPORT_BUFFER | 3
| | linux/io_uring.h | io_send_setup | 1
| | linux/io_uring.h | io_sendmsg_setup | 1
| | linux/io_uring.h | io_notif_account_mem | 1
| | linux/io_uring.h | MAX_SKB_FRAGS | 1
| | linux/io_uring.h | skb_shinfo | 1
| | linux/io_uring.h | skb_zcopy_downgrade_managed | 1
| | linux/io_uring.h | zerocopy_fill_skb_from_iter | 2
| | linux/io_uring.h | skb_zcopy_managed | 1
| | linux/io_uring.h | mp_bvec_iter_bvec | 1
| | linux/io_uring.h | PAGE_ALIGN | 1
| | linux/io_uring.h | __skb_fill_page_desc_noacc | 1
| | linux/io_uring.h | bvec_iter_advance_single | 1
| | linux/io_uring.h | ITER_SOURCE | 2
| | linux/io_uring.h | io_import_reg_buf | 1
| | linux/io_uring.h | MSG_WAITALL | 3
| | linux/io_uring.h | MSG_INTERNAL_SENDMSG_FLAGS | 2
| | linux/io_uring.h | IORING_CQE_F_MORE | 3
| | linux/io_uring.h | io_import_reg_vec | 1
| | linux/io_uring.h | rlimit | 1
| | linux/io_uring.h | __get_unused_fd_flags | 2
| | linux/io_uring.h | SOCK_CLOEXEC | 2
| | linux/io_uring.h | IORING_FILE_INDEX_ALLOC | 1
| | linux/io_uring.h | SOCK_NONBLOCK | 2
| | linux/io_uring.h | O_NONBLOCK | 2
| | linux/io_uring.h | do_accept | 1
| | linux/io_uring.h | put_unused_fd | 1
| | linux/io_uring.h | PTR_ERR | 1
| | linux/io_uring.h | fd_install | 1
| | linux/io_uring.h | io_fixed_fd_install | 2
| | linux/io_uring.h | IORING_CQE_F_SOCK_NONEMPTY | 2
| | linux/io_uring.h | __sys_socket_file | 1
| | linux/io_uring.h | SOCK_TYPE_MASK | 1
| | linux/io_uring.h | move_addr_to_kernel | 2
| | linux/io_uring.h | REQ_F_FAIL | 1
| | io_uring.h | req_has_async_data | 1
| | io_uring.h | io_netmsg_iovec_free | 1
| | io_uring.h | io_alloc_async_data | 1
| | io_uring.h | io_msg_alloc_async | 2
| | io_uring.h | io_do_buffer_select | 0
| | io_uring.h | import_iovec | 0
| | io_uring.h | __import_iovec | 0
| | io_uring.h | __get_compat_msghdr | 0
| | io_uring.h | __copy_msghdr | 0
| | io_uring.h | io_prep_reg_iovec | 0
| | io_uring.h | io_buffers_select | 0
| | io_uring.h | io_buffers_peek | 0
| | kbuf.h | io_vec_free | 1
| | alloc_cache.h | io_alloc_cache_vec_kasan | 0
| | alloc_cache.h | io_alloc_cache_put | 0
| | alloc_cache.h | io_uring_alloc_async_data | 0
| | net.h | /* (No functions used) */ | 0
| | notif.h | io_notif_to_data | 1
| | rsrc.h | /* (No functions used) */ | 0
| | zcrx.h | io_zcrx_recv | 1

### nop.c
Source | Library | Function utilized | Time Used
-------|---------|-------------------|-----------
nop.c | <linux/kernel.h> | printk | 1
| <linux/errno.h> | -EINVAL | 1
| <linux/errno.h> | -EBADF | 1
| <linux/errno.h> | -EFAULT | 1
| <linux/fs.h> | io_file_get_fixed | 1
| <linux/fs.h> | io_file_get_normal | 1
| <linux/fs.h> | io_find_buf_node | 1
| <linux/io_uring.h> | io_kiocb_to_cmd | 2
| <linux/io_uring.h> | io_req_set_res | 1
| <linux/io_uring.h> | req_set_fail | 1
| "io_uring.h" | io_file_get_fixed | 1
| "io_uring.h" | io_file_get_normal | 1
| "io_uring.h" | io_find_buf_node | 1


### notif.c
Source | Library | Function utilized | Time Used
-------|---------|-------------------|-----------
notif.c | linux/kernel.h | printk | 1
| linux/errno.h | -EINVAL | 1
| linux/errno.h | -EEXIST | 3
| linux/slab.h | kmem_cache_alloc | 1
| linux/slab.h | kmem_cache_free | 1
| linux/net.h | skb_zcopy | 1
| linux/net.h | net_zcopy_get | 2
| linux/io_uring.h | io_kiocb_to_cmd | 1
| linux/io_uring.h | io_req_task_complete | 1
| linux/io_uring.h | io_get_task_refs | 1
| linux/io_uring.h | io_alloc_req | 1
| io_uring.h | io_notif_to_data | 3
| notif.h | io_tx_ubuf_complete | 1
| notif.h | io_link_skb | 2
| notif.h | io_alloc_notif | 1


### opdef.c
Source | Library | Function utilized | Time Used
-------|--------|--------------| ------------------
opdef.c | linux/kernel.h | WARN_ON_ONCE | 2
| | linux/errno.h | -ECANCELED | 1
| | linux/errno.h | -EOPNOTSUPP | 18
| | linux/fs.h | /* (No functions used) */ | 0
| | linux/file.h | /* (No functions used)*/ | 0
| | linux/io_uring.h | IORING_OP_NOP | 2
| | linux/io_uring.h | IORING_OP_READV | 2
| | linux/io_uring.h | IORING_OP_WRITEV | 2
| | linux/io_uring.h | IORING_OP_FSYNC | 2
| | linux/io_uring.h | IORING_OP_READ_FIXED | 2
| | linux/io_uring.h | IORING_OP_WRITE_FIXED | 2
| | linux/io_uring.h | IORING_OP_POLL_ADD | 2
| | linux/io_uring.h | IORING_OP_POLL_REMOVE | 2
| | linux/io_uring.h | IORING_OP_SYNC_FILE_RANGE | 2
| | linux/io_uring.h | IORING_OP_SENDMSG | 2
| | linux/io_uring.h | IORING_OP_RECVMSG | 2
| | linux/io_uring.h | IORING_OP_TIMEOUT | 2
| | linux/io_uring.h | IORING_OP_TIMEOUT_REMOVE | 2
| | linux/io_uring.h | IORING_OP_ACCEPT | 2
| | linux/io_uring.h | IORING_OP_ASYNC_CANCEL | 2
| | linux/io_uring.h | IORING_OP_LINK_TIMEOUT | 2
| | linux/io_uring.h | IORING_OP_CONNECT | 2
| | linux/io_uring.h | IORING_OP_FALLOCATE | 2
| | linux/io_uring.h | IORING_OP_OPENAT | 2
| | linux/io_uring.h | IORING_OP_CLOSE | 2
| | linux/io_uring.h | IORING_OP_FILES_UPDATE | 2
| | linux/io_uring.h | IORING_OP_STATX | 2
| | linux/io_uring.h | IORING_OP_READ | 2
| | linux/io_uring.h | IORING_OP_WRITE | 2
| | linux/io_uring.h | IORING_OP_FADVISE | 2
| | linux/io_uring.h | IORING_OP_MADVISE | 2
| | linux/io_uring.h | IORING_OP_SEND | 2
| | linux/io_uring.h | IORING_OP_RECV | 2
| | linux/io_uring.h | IORING_OP_OPENAT2 | 2
| | linux/io_uring.h | IORING_OP_EPOLL_CTL | 2
| | linux/io_uring.h | IORING_OP_SPLICE | 2
| | linux/io_uring.h | IORING_OP_PROVIDE_BUFFERS | 2
| | linux/io_uring.h | IORING_OP_REMOVE_BUFFERS | 2
| | linux/io_uring.h | IORING_OP_TEE | 2
| | linux/io_uring.h | IORING_OP_SHUTDOWN | 2
| | linux/io_uring.h | IORING_OP_RENAMEAT | 2
| | linux/io_uring.h | IORING_OP_UNLINKAT | 2
| | linux/io_uring.h | IORING_OP_MKDIRAT | 2
| | linux/io_uring.h | IORING_OP_SYMLINKAT | 2
| | linux/io_uring.h | IORING_OP_LINKAT | 2
| | linux/io_uring.h | IORING_OP_MSG_RING | 2
| | linux/io_uring.h | IORING_OP_FSETXATTR | 2
| | linux/io_uring.h | IORING_OP_SETXATTR | 2
| | linux/io_uring.h | IORING_OP_FGETXATTR | 2
| | linux/io_uring.h | IORING_OP_GETXATTR | 2
| | linux/io_uring.h | IORING_OP_SOCKET | 2
| | linux/io_uring.h | IORING_OP_URING_CMD | 2
| | linux/io_uring.h | IORING_OP_SEND_ZC | 2
| | linux/io_uring.h | IORING_OP_SENDMSG_ZC | 2
| | linux/io_uring.h | IORING_OP_READ_MULTISHOT | 2
| | linux/io_uring.h | IORING_OP_WAITID | 2
| | linux/io_uring.h | IORING_OP_FUTEX_WAIT | 2
| | linux/io_uring.h | IORING_OP_FUTEX_WAKE | 2
| | linux/io_uring.h | IORING_OP_FUTEX_WAITV | 2
| | linux/io_uring.h | IORING_OP_FIXED_FD_INSTALL | 2
| | linux/io_uring.h | IORING_OP_FTRUNCATE | 2
| | linux/io_uring.h | IORING_OP_BIND | 2
| | linux/io_uring.h | IORING_OP_LISTEN | 2
| | linux/io_uring.h | IORING_OP_RECV_ZC | 2
| | linux/io_uring.h | IORING_OP_EPOLL_WAIT | 2
| | linux/io_uring.h | IORING_OP_READV_FIXED | 2
| | linux/io_uring.h | IORING_OP_WRITEV_FIXED | 2
| | linux/io_uring/cmd.h | struct io_async_rw | 6
| | linux/io_uring/cmd.h | struct io_async_msghdr | 6
| | linux/io_uring/cmd.h | struct io_timeout_data | 2
| | linux/io_uring/cmd.h | struct io_async_cmd | 1
| | linux/io_uring/cmd.h | struct io_waitid_async | 1
| | io_uring.h | io_nop_prep | 1
| | io_uring.h | io_nop | 1
| | io_uring.h | io_prep_readv | 1
| | io_uring.h | io_read | 2
| | io_uring.h | io_prep_writev | 1
| | io_uring.h | io_write | 2
| | io_uring.h | io_fsync_prep | 1
| | io_uring.h | io_fsync | 1
| | io_uring.h | io_prep_read_fixed | 1
| | io_uring.h | io_read_fixed | 1
| | io_uring.h | io_prep_write_fixed | 1
| | io_uring.h | io_write_fixed | 1
| | io_uring.h | io_poll_add_prep | 1
| | io_uring.h | io_poll_add | 1
| | io_uring.h | io_poll_remove_prep | 1
| | io_uring.h | io_poll_remove | 1
| | io_uring.h | io_sfr_prep | 1
| | io_uring.h | io_sync_file_range | 1
| | io_uring.h | io_sendmsg_prep | 2
| | io_uring.h | io_sendmsg | 1
| | io_uring.h | io_recvmsg_prep | 2
| | io_uring.h | io_recvmsg | 1
| | io_uring.h | io_timeout_prep | 1
| | io_uring.h | io_timeout | 1
| | io_uring.h | io_timeout_remove_prep | 1
| | io_uring.h | io_timeout_remove | 1
| | io_uring.h | io_accept_prep | 1
| | io_uring.h | io_accept | 1
| | io_uring.h | io_async_cancel_prep | 1
| | io_uring.h | io_async_cancel | 1
| | io_uring.h | io_link_timeout_prep | 1
| | io_uring.h | io_no_issue | 1
| | io_uring.h | io_connect_prep | 1
| | io_uring.h | io_connect | 1
| | io_uring.h | io_fallocate_prep | 1
| | io_uring.h | io_fallocate | 1
| | io_uring.h | io_openat_prep | 1
| | io_uring.h | io_openat | 1
| | io_uring.h | io_close_prep | 1
| | io_uring.h | io_close | 1
| | io_uring.h | io_files_update_prep | 1
| | io_uring.h | io_files_update | 1
| | io_uring.h | io_statx_prep | 1
| | io_uring.h | io_statx | 1
| | io_uring.h | io_prep_read | 1
| | io_uring.h | io_prep_write | 1
| | io_uring.h | io_fadvise_prep | 1
| | io_uring.h | io_fadvise | 1
| | io_uring.h | io_madvise_prep | 1
| | io_uring.h | io_madvise | 1
| | io_uring.h | io_send_prep | 1
| | io_uring.h | io_send | 1
| | io_uring.h | io_recv_prep | 1
| | io_uring.h | io_recv | 1
| | io_uring.h | io_openat2_prep | 1
| | io_uring.h | io_openat2 | 1
| | io_uring.h | io_epoll_ctl_prep | 1
| | io_uring.h | io_epoll_ctl | 1
| | io_uring.h | io_splice_prep | 1
| | io_uring.h | io_splice | 1
| | io_uring.h | io_provide_buffers_prep | 1
| | io_uring.h | io_provide_buffers | 1
| | io_uring.h | io_remove_buffers_prep | 1
| | io_uring.h | io_remove_buffers | 1
| | io_uring.h | io_tee_prep | 1
| | io_uring.h | io_tee | 1
| | io_uring.h | io_shutdown_prep | 1
| | io_uring.h | io_shutdown | 1
| | io_uring.h | io_renameat_prep | 1
| | io_uring.h | io_renameat | 1
| | io_uring.h | io_unlinkat_prep | 1
| | io_uring.h | io_unlinkat | 1
| | io_uring.h | io_mkdirat_prep | 1
| | io_uring.h | io_mkdirat | 1
| | io_uring.h | io_symlinkat_prep | 1
| | io_uring.h | io_symlinkat | 1
| | io_uring.h | io_linkat_prep | 1
| | io_uring.h | io_linkat | 1
| | io_uring.h | io_msg_ring_prep | 1
| | io_uring.h | io_msg_ring | 1
| | io_uring.h | io_fsetxattr_prep | 1
| | io_uring.h | io_fsetxattr | 1
| | io_uring.h | io_setxattr_prep | 1
| | io_uring.h | io_setxattr | 1
| | io_uring.h | io_fgetxattr_prep | 1
| | io_uring.h | io_fgetxattr | 1
| | io_uring.h | io_getxattr_prep | 1
| | io_uring.h | io_getxattr | 1
| | io_uring.h | io_socket_prep | 1
| | io_uring.h | io_socket | 1
| | io_uring.h | io_uring_cmd_prep | 1
| | io_uring.h | io_uring_cmd | 1
| | io_uring.h | io_send_zc_prep | 2
| | io_uring.h | io_send_zc | 1
| | io_uring.h | io_sendmsg_zc | 1
| | io_uring.h | io_read_mshot_prep | 1
| | io_uring.h | io_read_mshot | 1
| | io_uring.h | io_waitid_prep | 1
| | io_uring.h | io_waitid | 1
| | io_uring.h | io_futex_prep | 2
| | io_uring.h | io_futex_wait | 1
| | io_uring.h | io_futex_wake | 1
| | io_uring.h | io_futexv_prep | 1
| | io_uring.h | io_futexv_wait | 1
| | io_uring.h | io_install_fixed_fd_prep | 1
| | io_uring.h | io_install_fixed_fd | 1
| | io_uring.h | io_ftruncate_prep | 1
| | io_uring.h | io_ftruncate | 1
| | io_uring.h | io_bind_prep | 1
| | io_uring.h | io_bind | 1
| | io_uring.h | io_listen_prep | 1
| | io_uring.h | io_listen | 1
| | io_uring.h | io_recvzc_prep | 1
| | io_uring.h | io_recvzc | 1
| | io_uring.h | io_epoll_wait_prep | 1
| | io_uring.h | io_epoll_wait | 1
| | io_uring.h | io_prep_readv_fixed | 1
| | io_uring.h | io_prep_writev_fixed | 1
| | io_uring.h | io_readv_writev_cleanup | 6
| | io_uring.h | io_rw_fail | 6
| | io_uring.h | io_sendmsg_recvmsg_cleanup | 4
| | io_uring.h | io_sendrecv_fail | 4
| | io_uring.h | io_open_cleanup | 2
| | io_uring.h | io_statx_cleanup | 1
| | io_uring.h | io_splice_cleanup | 2
| | io_uring.h | io_renameat_cleanup | 1
| | io_uring.h | io_unlinkat_cleanup | 1
| | io_uring.h | io_mkdirat_cleanup | 1
| | io_uring.h | io_link_cleanup | 2
| | io_uring.h | io_msg_ring_cleanup | 1
| | io_uring.h | io_uring_cmd_cleanup | 1
| | io_uring.h | io_send_zc_cleanup | 2
| | opdef.h | /* (No functions used) */ | 0
| | refs.h | /* (No functions used) */ | 0
| | tctx.h | /* (No functions used) */ | 0
| | sqpoll.h | /* (No functions used) */ | 0
| | fdinfo.h | /* (No functions used) */ | 0

### openclose.c
Source | Library | Function utilized | Time Used
-------|--------|--------------------|-----------
openclose.c | fs/open.c | do_filp_open | 1
 | fs/file_table.c | filp_close | 1
 | fs/file_table.c | f_op->flush | 1
 | fs/file_table.c | file->f_flags (field access) | 1
| fs/file_table.c | fd_install | 1
 | fs/file_table.c | put_unused_fd | 1
| fs/namei.c | build_open_flags | 1
 | fs/namei.c | build_open_how | 1
 | fs/namei.c | getname | 1
 | fs/namei.c | putname | 2
 | fs/file.c | __get_unused_fd_flags | 1
| fs/file.c | files_lookup_fd_locked | 1
 | fs/file.c | file_close_fd_locked | 1
 | kernel/fdtable.c | __close_fd | 1
 | fs/io_uring.c | io_fixed_fd_install | 1
 | fs/io_uring.c | io_fixed_fd_remove | 1
| fs/io_uring.c | io_ring_submit_lock | 1
| fs/io_uring.c | io_ring_submit_unlock | 1
| fs/io_uring.c | io_kiocb_to_cmd | 4
| fs/io_uring.c | io_req_set_res | 2
 | fs/io_uring.c | req_set_fail | 2
 | kernel/resource.c | force_o_largefile | 1
| arch/x86/include/asm/uaccess.h | u64_to_user_ptr | 2
| kernel/sys.c | rlimit (macro for RLIMIT_NOFILE) | 1
| lib/user.c | copy_struct_from_user | 1
 | kernel/sched/current.c | current->files | 2
| kernel/locking/spinlock.c | spin_lock | 1
| kernel/locking/spinlock.c | spin_unlock | 1
 | fs/io_uring.c | io_is_uring_fops | 1
| kernel/printk.c | WARN_ON_ONCE | 1

### poll.c
Source | Library | Function utilized | Time Used
-------|--------|--------------| ------------------
poll.c | linux/kernel.h | BIT | 3
| | linux/kernel.h | GENMASK | 1
| | linux/kernel.h | container_of | 2
| | linux/kernel.h | unlikely | 10
| | linux/kernel.h | WARN_ON_ONCE | 1
| | linux/errno.h | -ECANCELED | 2
| | linux/errno.h | -EINVAL | 8
| | linux/errno.h | -ENOMEM | 1
| | linux/errno.h | -ENOENT | 2
| | linux/errno.h | -EALREADY | 1
| | linux/errno.h | -EFAULT | 1
| | linux/fs.h | vfs_poll | 2
| | linux/file.h | io_file_can_poll | 1
| | linux/mm.h | kmalloc | 1
| | linux/slab.h | kfree | 2
| | linux/poll.h | poll_table_struct | 2
| | linux/poll.h | init_waitqueue_func_entry | 1
| | linux/poll.h | add_wait_queue_exclusive | 1
| | linux/poll.h | add_wait_queue | 1
| | linux/poll.h | list_del_init | 2
| | linux/hashtable.h | hash_long | 2
| | linux/hashtable.h | hlist_add_head | 1
| | linux/hashtable.h | hlist_for_each_entry_safe | 1
| | linux/hashtable.h | hlist_del_init | 1
| | linux/hashtable.h | hlist_for_each_entry | 2
| | linux/hashtable.h | hash_del | 2
| | linux/io_uring.h | io_kiocb_to_cmd | 6
| | linux/io_uring.h | trace_io_uring_task_add | 1
| | linux/io_uring.h | __io_req_task_work_add | 1
| | linux/io_uring.h | io_req_set_res | 6
| | linux/io_uring.h | io_should_terminate_tw | 1
| | linux/io_uring.h | req_set_fail | 3
| | linux/io_uring.h | mangle_poll | 2
| | linux/io_uring.h | io_req_post_cqe | 1
| | linux/io_uring.h | io_poll_issue | 1
| | linux/io_uring.h | io_napi_add | 2
| | linux/io_uring.h | io_kbuf_recycle | 2
| | linux/io_uring.h | __io_poll_execute | 3
| | linux/io_uring.h | io_req_task_submit | 2
| | linux/io_uring.h | io_req_defer_failed | 1
| | linux/io_uring.h | io_tw_lock | 1
| | linux/io_uring.h | key_to_poll | 1
| | linux/io_uring.h | smp_store_release | 1
| | linux/io_uring.h | atomic_fetch_or | 1
| | linux/io_uring.h | atomic_fetch_inc | 1
| | linux/io_uring.h | atomic_read | 2
| | linux/io_uring.h | atomic_or | 1
| | linux/io_uring.h | atomic_andnot | 1
| | linux/io_uring.h | atomic_sub_return | 1
| | linux/io_uring.h | atomic_set | 1
| | linux/io_uring.h | atomic_cmpxchg | 1
| | linux/io_uring.h | rcu_read_lock | 2
| | linux/io_uring.h | smp_load_acquire | 2
| | linux/io_uring.h | spin_lock_irq | 2
| | linux/io_uring.h | spin_unlock_irq | 2
| | linux/io_uring.h | rcu_read_unlock | 2
| | linux/io_uring.h | lockdep_assert_held | 1
| | linux/io_uring.h | io_ring_submit_lock | 2
| | linux/io_uring.h | io_ring_submit_unlock | 2
| | linux/io_uring.h | io_match_task_safe | 1
| | linux/io_uring.h | io_cancel_match_sequence | 1
| | linux/io_uring.h | io_cancel_req_match | 1
| | linux/io_uring.h | swahw32 | 1
| | linux/io_uring.h | demangle_poll | 1
| | trace/events/io_uring.h | trace_io_uring_poll_arm | 1
| | alloc_cache.h | io_cache_alloc | 1
| | alloc_cache.h | io_cache_free | 1
| | refs.h | /* (No functions used) */ | 0
| | napi.h | /* (No functions used) */ | 0
| | opdef.h | /* (No functions used) */ | 0
| | kbuf.h | /* (No functions used) */ | 0
| | poll.h | /* (No functions used) */ | 0
| | cancel.h | io_cancel_match_sequence | 1

### register.c
Source | Library | Function utilized | Time Used
-------|--------|--------------| ------------------
register.c | linux/kernel.h | __cold | 6
| | linux/kernel.h | array_size | 2
| | linux/kernel.h | BUILD_BUG_ON | 1
| | linux/kernel.h | memchr_inv | 3
| | linux/kernel.h | WARN_ON_ONCE | 2
| | linux/kernel.h | offsetof | 1
| | linux/errno.h | -ENOMEM | 2
| | linux/errno.h | -EFAULT | 11
| | linux/errno.h | -EINVAL | 25
| | linux/errno.h | -EOVERFLOW | 2
| | linux/errno.h | -EBADFD | 2
| | linux/errno.h | -EBUSY | 1
| | linux/errno.h | -EEXIST | 2
| | linux/errno.h | -EACCES | 1
| | linux/errno.h | -ENXIO | 1
| | linux/errno.h | -EBADF | 1
| | linux/errno.h | -EOPNOTSUPP | 1
| | linux/syscalls.h | SYSCALL_DEFINE4 | 1
| | linux/refcount.h | refcount_inc | 1
| | linux/bits.h | __set_bit | 2
| | linux/fs.h | io_uring_op_supported | 1
| | linux/file.h | fget | 1
| | linux/file.h | fput | 2
| | linux/slab.h | kzalloc | 1
| | linux/slab.h | kfree | 2
| | linux/uaccess.h | copy_from_user | 8
| | linux/uaccess.h | copy_to_user | 4
| | linux/nospec.h | array_index_nospec | 2
| | linux/compat.h | in_compat_syscall | 1
| | linux/compat.h | compat_get_bitmap | 1
| | linux/io_uring.h | struct_size | 1
| | linux/io_uring.h | IO_URING_OP_LAST | 2
| | linux/io_uring.h | IO_URING_OP_SUPPORTED | 1
| | linux/io_uring.h | xa_erase | 1
| | linux/io_uring.h | get_current_cred | 1
| | linux/io_uring.h | put_cred | 2
| | linux/io_uring.h | xa_alloc_cyclic | 1
| | linux/io_uring.h | USHRT_MAX | 1
| | linux/io_uring.h | memdup_user | 1
| | linux/io_uring.h | PTR_ERR | 2
| | linux/io_uring.h | IS_ERR | 2
| | linux/io_uring.h | memset | 2
| | linux/io_uring.h | WRITE_ONCE | 7
| | linux/io_uring.h | get_task_struct | 1
| | linux/io_uring.h | wq_has_sleeper | 2
| | linux/io_uring.h | io_activate_pollwq | 1
| | linux/io_uring.h | wake_up | 1
| | linux/io_uring.h | alloc_cpumask_var | 1
| | linux/io_uring.h | cpumask_clear | 1
| | linux/io_uring.h | cpumask_size | 1
| | linux/io_uring.h | cpumask_bits | 1
| | linux/io_uring.h | free_cpumask_var | 2
| | linux/io_uring.h | io_wq_cpu_affinity | 1
| | linux/io_uring.h | io_sqpoll_wq_cpu_affinity | 1
| | linux/io_uring.h | io_put_sq_data | 2
| | linux/io_uring.h | list_for_each_entry | 1
| | linux/io_uring.h | io_wq_max_workers | 2
| | linux/io_uring.h | PAGE_ALIGN | 1
| | linux/io_uring.h | rings_size | 1
| | linux/io_uring.h | io_create_region_mmap_safe | 2
| | linux/io_uring.h | io_region_get_ptr | 2
| | linux/io_uring.h | io_uring_fill_params | 1
| | linux/io_uring.h | READ_ONCE | 10
| | linux/io_uring.h | atomic_set | 1
| | linux/io_uring.h | atomic_read | 1
| | linux/io_uring.h | io_sq_thread_park | 1
| | linux/io_uring.h | spin_lock | 1
| | linux/io_uring.h | spin_unlock | 1
| | linux/io_uring.h | mutex_lock | 3
| | linux/io_uring.h | mutex_unlock | 3
| | linux/io_uring.h | io_sq_thread_unpark | 1
| | linux/io_uring.h | io_free_region | 2
| | linux/io_uring.h | io_region_is_set | 1
| | linux/io_uring.h | percpu_ref_is_dying | 1
| | linux/io_uring.h | test_bit | 1
| | linux/io_uring.h | io_sqe_buffers_register | 1
| | linux/io_uring.h | io_sqe_buffers_unregister | 1
| | linux/io_uring.h | io_sqe_files_register | 1
| | linux/io_uring.h | io_sqe_files_unregister | 1
| | linux/io_uring.h | trace_io_uring_register | 1
| | linux/io_uring.h | io_is_uring_fops | 1
| | io_uring.h | IORING_RESTRICTION_LAST | 1
| | io_uring.h | IORING_REGISTER_LAST | 2
| | io_uring.h | IORING_RESTRICTION_REGISTER_OP | 1
| | io_uring.h | IORING_RESTRICTION_SQE_OP | 1
| | io_uring.h | IORING_RESTRICTION_SQE_FLAGS_ALLOWED | 1
| | io_uring.h | IORING_RESTRICTION_SQE_FLAGS_REQUIRED | 1
| | io_uring.h | IORING_SETUP_R_DISABLED | 2
| | io_uring.h | IORING_SETUP_SINGLE_ISSUER | 1
| | io_uring.h | IORING_SETUP_SQPOLL | 1
| | io_uring.h | IORING_SETUP_CQSIZE | 1
| | io_uring.h | IORING_SETUP_CLAMP | 1
| | io_uring.h | IORING_SETUP_NO_SQARRAY | 1
| | io_uring.h | IORING_SETUP_SQE128 | 1
| | io_uring.h | IORING_SETUP_CQE32 | 1
| | io_uring.h | IORING_SETUP_NO_MMAP | 2
| | io_uring.h | IORING_SETUP_DEFER_TASKRUN | 1
| | io_uring.h | IORING_OFF_CQ_RING | 1
| | io_uring.h | IORING_OFF_SQES | 1
| | io_uring.h | IORING_MEM_REGION_TYPE_USER | 2
| | io_uring.h | IORING_MAP_OFF_PARAM_REGION | 1
| | io_uring.h | IORING_MEM_REGION_REG_WAIT_ARG | 2
| | io_uring.h | IORING_REGISTER_USE_REGISTERED_RING | 1
| | io_uring.h | IO_RINGFD_REG_MAX | 2
| | io_uring.h | IORING_OP_MSG_RING | 1
| | opdef.h | /* (No functions used directly in this snippet) */ | 0
| | tctx.h | /* (No functions used directly in this snippet) */ | 0
| | rsrc.h | io_register_rsrc | 2
| | rsrc.h | io_register_rsrc_update | 2
| | sqpoll.h | /* (No functions used directly in this snippet) */ | 0
| | register.h | /* (No functions used directly in this snippet) */ | 0
| | cancel.h | io_sync_cancel | 1
| | kbuf.h | /* (No functions used directly in this snippet) */ | 0
| | napi.h | io_register_napi | 1
| | napi.h | io_unregister_napi | 1
| | eventfd.h | io_eventfd_register | 2
| | eventfd.h | io_eventfd_unregister | 1
| | msg_ring.h | io_uring_sync_msg_ring | 1
| | memmap.h | io_register_pbuf_ring | 1
| | memmap.h | io_unregister_pbuf_ring | 1
| | memmap.h | io_register_file_alloc_range | 1
| | memmap.h | io_register_pbuf_status | 1
| | memmap.h | io_register_clone_buffers | 1
| | zcrx.h | io_register_zcrx_ifq | 1
| | register.h | io_register_files_update | 1
| | register.h | io_ringfd_register | 1
| | register.h | io_ringfd_unregister | 1

### rsrc.c
Source | Library | Function utilized | Time Used
-------|--------|--------------| ------------------
rsrc.c | linux/kernel.h | swap | 1
| | linux/kernel.h | max | 1
| | linux/kernel.h | memcpy | 1
| | linux/errno.h | -EINVAL | 6
| | linux/errno.h | -EBUSY | 1
| | linux/errno.h | -ENOMEM | 1
| | linux/errno.h | -ENXIO | 1
| | linux/errno.h | -EOVERFLOW | 1
| | linux/errno.h | -EFAULT | 1
| | linux/fs.h | fget | 1
| | linux/file.h | fput | 1
| | linux/slab.h | kmalloc_array | 1
| | linux/slab.h | kfree | 1
| | linux/nospec.h | /* (No functions used) */ | 0
| | linux/hugetlb.h | /* (No functions used) */ | 0
| | linux/compat.h | io_is_compat | 1
| | linux/io_uring.h | lockdep_assert_held | 2
| | linux/io_uring.h | io_rsrc_data_alloc | 1
| | linux/io_uring.h | min_t | 1
| | linux/io_uring.h | check_add_overflow | 2
| | linux/io_uring.h | io_rsrc_node_lookup | 1
| | linux/io_uring.h | io_rsrc_node_alloc | 1
| | linux/io_uring.h | refcount_inc | 1
| | linux/io_uring.h | io_rsrc_data_free | 1
| | linux/io_uring.h | WARN_ON_ONCE | 1
| | linux/io_uring.h | io_uring_register_get_file | 1
| | linux/io_uring.h | PTR_ERR | 1
| | linux/io_uring.h | IS_ERR | 1
| | linux/io_uring.h | memchr_inv | 1
| | linux/io_uring.h | mutex_lock | 1
| | linux/io_uring.h | mutex_lock_nested | 1
| | linux/io_uring.h | mutex_unlock | 2
| | linux/io_uring.h | bvec_set_page | 1
| | linux/io_uring.h | iov_iter_bvec | 1
| | linux/io_uring.h | bvec_iter_advance | 1
| | linux/io_uring.h | for_each_mp_bvec | 1
| | linux/io_uring.h | validate_fixed_range | 1
| | linux/io_uring.h | iovec_from_user | 1
| | io_uring.h | IORING_REGISTER_DST_REPLACE | 2
| | io_uring.h | IORING_MAX_REG_BUFFERS | 1
| | io_uring.h | IORING_REGISTER_SRC_REGISTERED | 1
| | io_uring.h | REQ_F_NEED_CLEANUP | 2
| | io_uring.h | REQ_F_IMPORT_BUFFER | 1
| | openclose.h | /* (No functions used) */ | 0
| | rsrc.h | io_vec_free | 1
| | rsrc.h | io_vec_realloc | 2
| | rsrc.h | validate_fixed_range | 1
| | rsrc.h | io_find_buf_node | 1
| | memmap.h | /* (No functions used) */ | 0
| | register.h | /* (No functions used) */ | 0

### rw.c

Source | Library | Function utilized | Time Used
-------|--------|--------------| ------------------
rw.c | linux/kernel.h | unlikely | 9
| | linux/kernel.h | container_of | 4
| | linux/errno.h | -EFAULT | 4
| | linux/errno.h | -EINVAL | 6
| | linux/errno.h | -ENOBUFS | 1
| | linux/errno.h | -ENOMEM | 1
| | linux/errno.h | -EAGAIN | 8
| | linux/errno.h | -EOPNOTSUPP | 4
| | linux/errno.h | -EBADF | 1
| | linux/errno.h | -EIOCBQUEUED | 2
| | linux/errno.h | -EINTR | 1
| | linux/errno.h | -EBADFD | 1
| | linux/fs.h | vfs_poll | 1
| | linux/fs.h | rw_verify_area | 2
| | linux/file.h | f_mode | 2
| | linux/file.h | f_pos | 1
| | linux/file.h | f_flags | 1
| | linux/file.h | f_op->read | 1
| | linux/file.h | f_op->write | 1
| | linux/file.h | f_op->read_iter | 1
| | linux/file.h | f_op->iopoll | 2
| | linux/file.h | f_op->fop_flags | 1
| | linux/file.h | file->f_op->uring_cmd_iopoll | 1
| | linux/blk-mq.h | /* (No functions used) */ | 0
| | linux/mm.h | import_ubuf | 2
| | linux/slab.h | /* (No functions used) */ | 0
| | linux/fsnotify.h | fsnotify_modify | 1
| | linux/fsnotify.h | fsnotify_access | 1
| | linux/poll.h | poll_table_struct | 1
| | linux/poll.h | _key | 1
| | linux/nospec.h | /* (No functions used) */ | 0
| | linux/compat.h | io_is_compat | 2
| | linux/compat.h | compat_iovec | 2
| | linux/io_uring/cmd.h | /* (No functions used) */ | 0
| | linux/indirect_call_wrapper.h | /* (No functions used) */ | 0
| | uapi/linux/io_uring.h | u64_to_user_ptr | 4
| | uapi/linux/io_uring.h | copy_from_user | 2
| | uapi/linux/io_uring.h | ITER_DEST | 3
| | uapi/linux/io_uring.h | ITER_SOURCE | 2
| | uapi/linux/io_uring.h | IORING_RW_ATTR_FLAG_PI | 1
| | io_uring.h | REQ_F_SUPPORT_NOWAIT | 1
| | io_uring.h | io_file_can_poll | 3
| | io_uring.h | io_kiocb_to_cmd | 8
| | io_uring.h | REQ_F_BUFFER_SELECT | 2
| | io_uring.h | io_buffer_select | 1
| | io_uring.h | __import_iovec | 1
| | io_uring.h | REQ_F_NEED_CLEANUP | 1
| | io_uring.h | io_vec_reset_iovec | 1
| | io_uring.h | iov_iter_save_state | 4
| | io_uring.h | io_alloc_cache_vec_kasan | 1
| | io_uring.h | io_vec_free | 2
| | io_uring.h | io_alloc_cache_put | 1
| | io_uring.h | io_uring_alloc_async_data | 1
| | io_uring.h | REQ_F_ASYNC_DATA | 1
| | io_uring.h | iov_iter_restore | 4
| | io_uring.h | REQ_F_HAS_METADATA | 2
| | io_uring.h | READ_ONCE | 7
| | io_uring.h | ioprio_check_cap | 1
| | io_uring.h | get_current_ioprio | 1
| | io_uring.h | IORING_SETUP_IOPOLL | 3
| | io_uring.h | io_complete_rw_iopoll | 2
| | io_uring.h | io_complete_rw | 2
| | io_uring.h | REQ_F_REISSUE | 2
| | io_uring.h | REQ_F_BL_NO_RECYCLE | 2
| | io_uring.h | req_set_fail | 2
| | io_uring.h | io_req_set_res | 4
| | io_uring.h | REQ_F_BUFFER_SELECTED | 1
| | io_uring.h | REQ_F_BUFFER_RING | 1
| | io_uring.h | io_put_kbuf | 6
| | io_uring.h | io_req_task_complete | 1
| | io_uring.h | __io_req_task_work_add | 1
| | io_uring.h | smp_store_release | 1
| | io_uring.h | REQ_F_CUR_POS | 1
| | io_uring.h | io_wq_current_is_worker | 1
| | io_uring.h | percpu_ref_is_dying | 1
| | io_uring.h | kiocb_end_write | 2
| | io_uring.h | iov_iter_count | 3
| | io_uring.h | iov_iter_advance | 2
| | io_uring.h | iter_is_ubuf | 1
| | io_uring.h | iter_iov_addr | 1
| | io_uring.h | iter_iov_len | 1
| | io_uring.h | io_req_task_queue | 1
| | io_uring.h | wake_page_match | 1
| | io_uring.h | list_del_init | 1
| | io_uring.h | INIT_LIST_HEAD | 1
| | io_uring.h | REQ_F_NOWAIT | 5
| | io_uring.h | io_file_get_flags | 1
| | io_uring.h | kiocb_set_rw_flags | 1
| | io_uring.h | REQ_F_FIXED_FILE | 1
| | io_uring.h | IOCB_ALLOC_CACHE | 1
| | io_uring.h | IOCB_NOWAIT | 5
| | io_uring.h | IOCB_DIRECT | 3
| | io_uring.h | IOCB_HIPRI | 3
| | io_uring.h | IORING_SETUP_HYBRID_IOPOLL | 2
| | io_uring.h | REQ_F_IOPOLL_STATE | 2
| | io_uring.h | ktime_get_ns | 2
| | io_uring.h | IOCB_HAS_METADATA | 2
| | io_uring.h | io_import_reg_buf | 1
| | io_uring.h | io_import_reg_vec | 2
| | io_uring.h | io_prep_reg_iovec | 1
| | io_uring.h | REQ_F_APOLL_MULTISHOT | 2
| | io_uring.h | lockdep_assert_held | 1
| | io_uring.h | FMODE_STREAM | 2
| | io_uring.h | file_inode | 3
| | io_uring.h | S_ISBLK | 2
| | io_uring.h | S_ISREG | 2
| | io_uring.h | IOCB_DIO_CALLER_COMP | 2
| | io_uring.h | cmd_to_io_kiocb | 2
| | io_uring.h | __io_complete_rw_common | 1
| | io_uring.h | FMODE_READ | 1
| | io_uring.h | FMODE_WRITE | 1
| | io_uring.h | O_NONBLOCK | 1
| | io_uring.h | READ | 1
| | io_uring.h | WRITE | 1
| | io_uring.h | FOP_BUFFER_RASYNC | 1
| | io_uring.h | IOU_OK | 1
| | io_uring.h | IOU_ISSUE_SKIP_COMPLETE | 2
| | io_uring.h | io_do_buffer_select | 2
| | io_uring.h | io_kbuf_recycle | 2
| | io_uring.h | IOU_RETRY | 3
| | io_uring.h | WARN_ON_ONCE | 1
| | io_uring.h | struct io_uring_cmd | 1
| | io_uring.h | hrtimer_setup_sleeper_on_stack | 1
| | io_uring.h | CLOCK_MONOTONIC | 1
| | io_uring.h | HRTIMER_MODE_REL | 1
| | io_uring.h | ktime_set | 1
| | io_uring.h | hrtimer_set_expires | 1
| | io_uring.h | set_current_state | 1
| | io_uring.h | TASK_INTERRUPTIBLE | 1
| | io_uring.h | hrtimer_sleeper_start_expires | 1
| | io_uring.h | io_schedule | 1
| | io_uring.h | hrtimer_cancel | 1
| | io_uring.h | __set_current_state | 1
| | io_uring.h | destroy_hrtimer_on_stack | 1
| | io_uring.h | DEFINE_IO_COMP_BATCH | 2
| | io_uring.h | BLK_POLL_ONESHOT | 2
| | io_uring.h | wq_list_for_each | 1
| | io_uring.h | wq_list_for_each_resume | 1
| | io_uring.h | smp_load_acquire | 1
| | io_uring.h | wq_list_cut | 1
| | io_uring.h | wq_list_empty | 2
| | io_uring.h | __io_submit_flush_completions | 1
| | io_uring.h | io_vec_free | 1
| | linux/poll.h | EPOLLOUT | 1
| | linux/slab.h | kfree | 1
| | linux/blk-mq.h | rq_list_empty | 1
| | linux/blk-mq.h | iob.complete | 1
| | linux/fs.h | file->f_op->uring_cmd_iopoll | 1
| | linux/file.h | file->f_op->iopoll | 1

### splice.c
Source | Library | Function utilized | Time Used
-------|--------|--------------------|-----------
splice.c | splice.c | __io_splice_prep | 3
| | splice.c | io_tee_prep | 1
| | splice.c | io_splice_cleanup | 1
| | splice.c | io_splice_get_file | 1
| | splice.c | io_tee | 1
| | splice.c | io_splice_prep | 1
| | splice.c | io_splice | 1
| | io_uring.h | io_kiocb_to_cmd | 7
| | io_uring.h | io_put_rsrc_node | 1
| | io_uring.h | io_ring_submit_lock | 1
| | io_uring.h | io_ring_submit_unlock | 1
| | io_uring.h | io_file_get_normal | 1
| | io_uring.h | io_rsrc_node_lookup | 1
| | io_uring.h | io_slot_file | 1
| | io_uring.h | req_set_fail | 2
| | io_uring.h | io_req_set_res | 2
| | linux/fs.h | fput | 2
| | linux/fs.h | do_splice | 1
| | linux/fs.h | do_tee | 1
| | linux/kernel.h | WARN_ON_ONCE | 2
| | uapi/linux/io_uring.h | READ_ONCE | 6


### sqpoll.c
Source | Library | Function utilized | Time Used
-------|--------|--------------------|-----------
sqpoll.c | linux/kernel.h | WARN_ON_ONCE | 6
| linux/kernel.h | data_race | 1
| linux/atomic.h | atomic_dec_return | 1
| linux/atomic.h | atomic_inc | 1
| linux/atomic.h | atomic_read | 1
| linux/bitops.h | clear_bit | 2
| linux/bitops.h | set_bit | 4
| linux/completion.h | wait_for_completion | 1
| linux/slab.h | kzalloc | 1
| linux/slab.h | kfree | 1
| linux/refcount.h | refcount_set | 1
| linux/refcount.h | refcount_inc | 1
| linux/refcount.h | refcount_dec_and_test | 1
| linux/mutex.h | mutex_lock | 8
| linux/mutex.h | mutex_unlock | 6
| linux/wait.h | wake_up | 3
| linux/wait.h | init_waitqueue_head | 1
| linux/wait.h | wait_event | 1
| linux/list.h | list_for_each_entry | 1
| linux/list.h | list_del_init | 1
| linux/list.h | INIT_LIST_HEAD | 1
| linux/sched/signal.h | signal_pending | 2
| linux/sched/signal.h | get_signal | 1
| linux/rcupdate.h | current | 6
| linux/sched.h | wake_up_process | 2
| linux/sched.h | task_work_pending | 1
| linux/sched.h | task_work_run | 1
| linux/cred.h | current_cred | 1
| linux/cred.h | override_creds | 1
| linux/cred.h | revert_creds | 1
| linux/uaccess.h | PTR_ERR | 1
| linux/err.h | IS_ERR | 1
| linux/err.h | ERR_PTR | 4
| linux/string.h | snprintf | 1
| linux/time.h | getrusage | 1
| linux/percpu-refcount.h | percpu_ref_is_dying | 1
| include/linux/io_uring_types.h | io_sq_data (struct usage) | many
| io_uring/io_uring.h | io_submit_sqes | 1
| io_uring/io_uring.h | io_do_iopoll | 1
| io_uring/io_uring.h | io_handle_tw_list | 1
| io_uring/io_uring.h | io_is_uring_fops | 1
| io_uring/io_uring.h | io_ring_exit_work | (referenced comment)
| io_uring/io_uring.h | io_ring_ctx (struct usage) | many
| io_uring/io_uring.h | io_sqring_entries | 1
| io_uring/io_uring.h | wq_list_empty | 2
| io_uring/io_uring.h | wq_has_sleeper | 1
| io_uring/io_uring.h | tctx_task_work_run | 1
| asm/processor.h | raw_smp_processor_id | 1
| linux/fdtable.h | fd_file | 2
| linux/fdtable.h | fd_empty | 1

### statx.c
Source | Library | Function utilized | Time Used
-------|--------|--------------------|------------
statx.c | linux/kernel.h | WARN_ON_ONCE | 1
 | linux/io_uring.h | io_kiocb_to_cmd | 3
 | linux/io_uring.h | io_req_set_res | 1
 | linux/io_uring.h | IOU_OK | 1
 | linux/io_uring.h | REQ_F_FIXED_FILE | 1
| linux/io_uring.h | REQ_F_NEED_CLEANUP | 1
| linux/io_uring.h | REQ_F_FORCE_ASYNC | 1
 | linux/io_uring.h | IO_URING_F_NONBLOCK | 1
| uapi/linux/io_uring.h | struct io_uring_sqe | 1
 | fs/internal.h | getname_uflags | 1
| fs/internal.h | putname | 1
 | linux/file.h | do_statx | 1
 | linux/uaccess.h | u64_to_user_ptr | 2
 | linux/compiler.h | READ_ONCE | 4
 | linux/err.h | IS_ERR | 1
 | linux/err.h | PTR_ERR | 1


### sync.c
Source | Library | Function utilized | Time Used
-------|--------|--------------| ------------------
sync.c | linux/kernel.h | unlikely | 3
| | linux/errno.h | -EINVAL | 3
| | linux/fs.h | /* No functions used */ | 0
| | linux/file.h | /* No functions used  */ | 0
| | linux/mm.h | /* No functions used*/ | 0
| | linux/slab.h | /* No functions used  */ | 0
| | linux/namei.h | /* No functions used */ | 0
| | linux/io_uring.h | /* No functions used */ | 0
| | linux/fsnotify.h | fsnotify_modify | 1
| | uapi/linux/io_uring.h | /* No functions used */ | 0
| | io_uring.h | io_kiocb_to_cmd | 3
| | io_uring.h | READ_ONCE | 6
| | io_uring.h | REQ_F_FORCE_ASYNC | 3
|  | io_uring.h | WARN_ON_ONCE | 3
|  | io_uring.h | io_req_set_res | 3
|  | io_uring.h | IOU_OK | 3
|  | io_uring.h | IORING_FSYNC_DATASYNC | 1
|  | linux/fs.h | vfs_fallocate | 1
|  | linux/fs.h | vfs_fsync_range | 1
|  | sync.h |  /* No functions used */ | 0

### tctx.c
Source | Library | Function utilized | Time Used
-------|--------|--------------| ------------------
tctx.c | linux/kernel.h | kzalloc | 2
| | linux/kernel.h | min | 1
| | linux/kernel.h | num_online_cpus | 1
| | linux/errno.h | -ENOMEM | 3
| | linux/errno.h | PTR_ERR | 1
| | linux/errno.h | IS_ERR | 1
| | linux/file.h | /* No functions used */ | 0
| | linux/mm.h | /* No functions used */ | 0
| | linux/slab.h | kfree | 4
| | linux/nospec.h | array_index_nospec | 1
| | linux/io_uring.h | io_wq_create | 1
| | linux/io_uring.h | mutex_lock | 4
| | linux/io_uring.h | mutex_unlock | 4
| | linux/io_uring.h | refcount_set | 1
| | linux/io_uring.h | init_waitqueue_head | 2
| | linux/io_uring.h | io_wq_free_work | 1
| | linux/io_uring.h | io_wq_submit_work | 1
| | linux/io_uring.h | xa_for_each | 1
| | linux/io_uring.h | WARN_ON_ONCE | 5
| | linux/io_uring.h | percpu_counter_destroy | 2
| | linux/io_uring.h | percpu_counter_init | 1
| | linux/io_uring.h | xa_init | 1
| | linux/io_uring.h | atomic_set | 2
| | linux/io_uring.h | init_llist_head | 1
| | linux/io_uring.h | init_task_work | 1
| | io_uring.h | io_init_wq_offload | 1
| | io_uring.h | io_wq_put_and_exit | 1
| | io_uring.h | xa_load | 1
| | io_uring.h | kmalloc | 1
| | io_uring.h | xa_err | 1
| | io_uring.h | xa_store | 1
| | io_uring.h | list_add | 1
| | io_uring.h | current | 4
| | io_uring.h | io_uring_alloc_task_context | 2
| | io_uring.h | io_wq_max_workers | 1
| | io_uring.h | IORING_SETUP_SINGLE_ISSUER | 1
| | io_uring.h | xa_erase | 1
| | io_uring.h | list_del | 1
| | io_uring.h | cond_resched | 1
| | io_uring.h | fput | 5
| | io_uring.h | fget | 1
| | io_uring.h | io_is_uring_fops | 1
| | uapi/linux/io_uring.h | /* No functions used */ | 0
| | tctx.h | tctx_task_work | 1
| | tctx.h | /* No other functions used */ | 0

### timeout.c
Source | Library | Function utilized | Time Used
-------|--------|--------------| ------------------
timeout.c | linux/kernel.h | /* No functions used */ | 0
| | linux/errno.h | -ETIME | 3
| | linux/errno.h | -ECANCELED | 4
| | linux/errno.h | -ENOENT | 1
| | linux/errno.h | -EALREADY | 2
| | linux/errno.h | -EINVAL | 5
| | linux/errno.h | -EFAULT | 2
| | linux/file.h | /* No functions used */ | 0
| | linux/io_uring.h | io_kiocb_to_cmd | 5
| | linux/io_uring.h | IORING_CQE_F_MORE | 1
| | linux/io_uring.h | raw_spin_lock_irq | 2
| | linux/io_uring.h | raw_spin_unlock_irq | 2
| | linux/io_uring.h | list_add | 1
| | linux/io_uring.h | hrtimer_start | 3
| | linux/io_uring.h | timespec64_to_ktime | 3
| | linux/io_uring.h | io_req_post_cqe | 1
| | linux/io_uring.h | io_req_task_complete | 3
| | linux/io_uring.h | list_empty | 2
| | linux/io_uring.h | list_first_entry | 1
| | linux/io_uring.h | list_del_init | 2
| | linux/io_uring.h | cmd_to_io_kiocb | 4
| | linux/io_uring.h | req_set_fail | 4
| | linux/io_uring.h | io_req_queue_tw_complete | 3
| | linux/io_uring.h | hrtimer_try_to_cancel | 3
| | linux/io_uring.h | atomic_set | 2
| | linux/io_uring.h | atomic_read | 3
| | linux/io_uring.h | list_move_tail | 1
| | linux/io_uring.h | raw_spin_lock_irqsave | 1
| | linux/io_uring.h | raw_spin_unlock_irqrestore | 1
| | linux/io_uring.h | container_of | 2
| | linux/io_uring.h | HRTIMER_NORESTART | 2
| | linux/io_uring.h | ERR_PTR | 2
| | linux/io_uring.h | IS_ERR | 1
| | linux/io_uring.h | PTR_ERR | 1
| | linux/io_uring.h | spin_lock | 1
| | linux/io_uring.h | spin_unlock | 1
| | linux/io_uring.h | HRTIMER_MODE_ABS | 2
| | linux/io_uring.h | HRTIMER_MODE_REL | 2
| | linux/io_uring.h | READ_ONCE | 3
| | linux/io_uring.h | unlikely | 1
| | linux/io_uring.h | INIT_LIST_HEAD | 1
| | linux/io_uring.h | WARN_ON_ONCE | 2
| | linux/io_uring.h | io_uring_alloc_async_data | 1
| | linux/io_uring.h | get_timespec64 | 2
| | linux/io_uring.h | u64_to_user_ptr | 1
| | linux/io_uring.h | list_for_each_prev | 1
| | linux/io_uring.h | list_entry | 1
| | linux/io_uring.h | data_race | 1
| | io_uring.h | io_queue_next | 1
| | io_uring.h | io_free_req | 1
| | io_uring.h | io_is_timeout_noseq | 3
| | io_uring.h | io_put_req | 2
| | io_uring.h | io_timeout_finish | 1
| | io_uring.h | io_req_set_res | 4
|  | io_uring.h | io_req_task_work_add | 3
|  | io_uring.h | io_should_terminate_tw | 1
|  | io_uring.h | io_try_cancel | 1
|  | io_uring.h | io_for_each_link | 1
|  | io_uring.h | req_ref_put_and_test | 1
|  | io_uring.h | req_has_async_data | 1
| | trace/events/io_uring.h | trace_io_uring_fail_link | 1
| | uapi/linux/io_uring.h | IORING_TIMEOUT_MULTISHOT | 4
| | uapi/linux/io_uring.h | IORING_TIMEOUT_CLOCK_MASK | 3
| | uapi/linux/io_uring.h | IORING_TIMEOUT_BOOTTIME | 1
| | uapi/linux/io_uring.h | IORING_TIMEOUT_REALTIME | 1
| | uapi/linux/io_uring.h | IORING_TIMEOUT_ABS | 2
| | uapi/linux/io_uring.h | IORING_TIMEOUT_ETIME_SUCCESS | 1
| | uapi/linux/io_uring.h | IORING_LINK_TIMEOUT_UPDATE | 1
| | refs.h | req_ref_inc_not_zero | 1
| | cancel.h | io_cancel_req_match | 1
| | timeout.h | /* No functions used */ | 0

### truncate.c
Source | Library | Function utilized | Time Used
-------|--------|--------------| ------------------
truncate.c | linux/kernel.h | /* No functions used */ | 0
| | linux/errno.h | -EINVAL | 1
| | linux/fs.h | /* No functions used */ | 0
| | linux/file.h | /* No functions used */ | 0
| | linux/mm.h | /* No functions used */ | 0
| | linux/slab.h | /* No functions used  */ | 0
| | linux/syscalls.h | do_ftruncate | 1
| | linux/io_uring.h | /* No functions used */ | 0
| | uapi/linux/io_uring.h | /* No functions used */ | 0
| | ../fs/internal.h | /* No functions used */ | 0
| | io_uring.h | io_kiocb_to_cmd | 2
| | io_uring.h | READ_ONCE | 1
| | io_uring.h | REQ_F_FORCE_ASYNC | 1
| | io_uring.h | WARN_ON_ONCE | 1
| | io_uring.h | io_req_set_res | 1
| | io_uring.h | IOU_OK | 1
| | truncate.h | /* No functions used */ | 0

### uring_cmd.c
Source | Library | Function utilized | Time Used
-------|--------|--------------| ------------------
uring_cmd.c | linux/kernel.h | /* No functions used */ | 0
| | linux/errno.h | -EINVAL | 4
| | linux/errno.h | -ENOMEM | 1
| | linux/errno.h | -EOPNOTSUPP | 4
| | linux/errno.h | -EAGAIN | 1
|  | linux/errno.h | -EIOCBQUEUED | 1
| | linux/file.h | /* No functions used directly */ | 0
| | linux/io_uring/cmd.h | /* No functions used */ | 0
| | linux/io_uring/net.h | /* No functions used */ | 0
| | linux/security.h | security_uring_cmd | 1
| | linux/nospec.h | /* No functions used */ | 0
| | net/sock.h | /* No functions used */ | 0
| | uapi/linux/io_uring.h | IORING_F_UNLOCKED | 2
| | uapi/linux/io_uring.h | IO_URING_F_CANCEL | 1
| | uapi/linux/io_uring.h | IO_URING_F_COMPLETE_DEFER | 2
| | uapi/linux/io_uring.h | IO_URING_F_TASK_DEAD | 1
| | uapi/linux/io_uring.h | IORING_URING_CMD_CANCELABLE | 4
| | uapi/linux/io_uring.h | IORING_URING_CMD_MASK | 1
| | uapi/linux/io_uring.h | IORING_URING_CMD_FIXED | 1
| | uapi/linux/io_uring.h | IORING_SETUP_CQE32 | 3
| | uapi/linux/io_uring.h | IORING_SETUP_IOPOLL | 2
| | uapi/linux/io_uring.h | IO_URING_F_SQE128 | 1
| | uapi/linux/io_uring.h | IO_URING_F_COMPAT | 3
| | uapi/linux/io_uring.h | IO_URING_F_IOPOLL | 1
| | asm/ioctls.h | SIOCINQ | 1
| | asm/ioctls.h | SIOCOUTQ | 1
| | asm/ioctls.h | SOL_SOCKET | 1
| | io_uring.h | io_kiocb_to_cmd | 7
| | io_uring.h | io_vec_free | 2
| | io_uring.h | kfree | 2
| | io_uring.h | io_alloc_cache_vec_kasan | 1
| | io_uring.h | io_alloc_cache_put | 1
| | io_uring.h | io_ring_submit_lock | 2
| | io_uring.h | io_ring_submit_unlock | 2
| | io_uring.h | hlist_for_each_entry_safe | 1
| | io_uring.h | file->f_op->uring_cmd | 3
| | io_uring.h | io_submit_flush_completions | 1
| | io_uring.h | hlist_del | 1
| | io_uring.h | hlist_add_head | 1
| | io_uring.h | EXPORT_SYMBOL_GPL | 4
| | io_uring.h | io_should_terminate_tw | 1
| | io_uring.h | __io_req_task_work_add | 1
| | io_uring.h | req->big_cqe.extra1 | 1
| | io_uring.h | req->big_cqe.extra2 | 1
| | io_uring.h | io_req_set_fail | 2
| | io_uring.h | io_req_set_res | 2
| | io_uring.h | smp_store_release | 1
| | io_uring.h | io_req_complete_defer | 1
| | io_uring.h | io_req_task_complete | 1
| | io_uring.h | io_uring_alloc_async_data | 1
| | io_uring.h | uring_sqe_size | 1
| | io_uring.h | memcpy | 1
| | io_uring.h | READ_ONCE | 9
| | io_uring.h | io_is_compat | 1
| | io_uring.h | u64_to_user_ptr | 2
|  | io_uring.h | USER_SOCKPTR | 2
|  | io_uring.h | KERNEL_SOCKPTR | 1
|  | io_uring.h | BUILD_BUG_ON | 1
|  | io_uring.h | offsetof | 1
|  | io_uring.h | io_import_reg_buf | 1
|  | io_uring.h | io_prep_reg_iovec | 1
|  | io_uring.h | io_import_reg_vec | 1
|  | io_uring.h | io_req_queue_iowq | 1
| rsrc.h | /* No functions used */ | 0
| uring_cmd.h | /* No functions used */ | 0
| alloc_cache.h | io_alloc_cache_get | 0
|  | io_alloc_cache_free | 1
|  | io_alloc_cache_get | 0

### waitid.c
Source | Library | Function utilized | Time Used
-------|--------|--------------| ------------------
waitid.c | linux/kernel.h | /* No functions used */ | 0
| | linux/errno.h | -EINVAL | 1
| | linux/fs.h | /* No functions used */ | 0
| | linux/file.h | /* No functions used */ | 0
| | linux/compat.h | /* No functions used */ | 0
| | linux/io_uring.h | /* No functions used */ | 0
| | uapi/linux/io_uring.h | /* No functions used */ | 0
| | io_uring.h | io_kiocb_to_cmd | 4
| | io_uring.h | io_uring_alloc_async_data | 2
| | io_uring.h | io_is_compat | 1
| | io_uring.h | user_write_access_begin | 2
| | io_uring.h | unsafe_put_user | 6
| | io_uring.h | user_write_access_end | 2
| | io_uring.h | put_pid | 1
| | io_uring.h | kfree | 1
| | io_uring.h | req->flags | 1
| | io_uring.h | atomic_read | 2
| | io_uring.h | lockdep_assert_held | 1
| | io_uring.h | hlist_del_init | 1
| | io_uring.h | req_set_fail | 2
| | io_uring.h | io_req_set_res | 2
|  | io_uring.h | io_req_queue_tw_complete | 1
| | io_uring.h | io_cancel_remove | 1
| | io_uring.h | io_cancel_remove_all | 1
| | io_uring.h | atomic_sub_return | 1
| | io_uring.h | io_req_task_work_add | 4
| | io_uring.h | remove_wait_queue | 2
| | io_uring.h | container_of | 2
| | io_uring.h | pid_child_should_wake | 1
| | io_uring.h | atomic_fetch_inc | 2
| | io_uring.h | spin_lock_irq | 1
| | io_uring.h | list_del_init | 2
| | io_uring.h | spin_unlock_irq | 1
| | io_uring.h | init_waitqueue_func_entry | 1
| | io_uring.h | add_wait_queue | 2
| | io_uring.h | __do_wait | 2
| | io_uring.h | io_tw_lock | 1
| | io_uring.h | io_tw_unlock | 0 /* Function not used */
| | ../kernel/exit.h | kernel_waitid_prepare | 1
| unistd.h | /* No functions used */ | 0

### xattr.c
Source | Library | Function utilized | Time Used
-------|--------|--------------| ------------------
xattr.c | linux/kernel.h | /* No functions used */ | 0
| | linux/errno.h | -EINVAL | 1
| | linux/fs.h | /* No functions used  */ | 0
| | linux/file.h | /* No functions used  */ | 0
| | linux/mm.h | /* No functions used  */ | 0
| | linux/slab.h | kfree | 2
| | linux/namei.h | /* No functions used  */ | 0
| | linux/io_uring.h | /* No functions used  */ | 0
| | linux/xattr.h | /* No functions used  */ | 0
| | uapi/linux/io_uring.h | /* No functions used  */ | 0
| | ../fs/internal.h | /* No functions used  */ | 0
| | io_uring.h | io_kiocb_to_cmd | 6
| | io_uring.h | putname | 1
| | io_uring.h | kvfree | 1
| | io_uring.h | req->flags | 4
| | io_uring.h | u64_to_user_ptr | 6
| | io_uring.h | kmalloc | 2
| | io_uring.h | import_xattr_name | 1
| | io_uring.h | REQ_F_NEED_CLEANUP | 2
| | io_uring.h | REQ_F_FORCE_ASYNC | 2
| | io_uring.h | EBADF | 2
| | io_uring.h | getname | 2
| | io_uring.h | IS_ERR | 2
| | io_uring.h | PTR_ERR | 2
| | io_uring.h | WARN_ON_ONCE | 4
| | io_uring.h | file_getxattr | 1
| | io_uring.h | io_xattr_cleanup | 2
| | io_uring.h | io_req_set_res | 4
| | io_uring.h | filename_getxattr | 1
| | io_uring.h | setxattr_copy | 1
| | io_uring.h | file_setxattr | 1
| | io_uring.h | filename_setxattr | 1

### zrcx.c
Source | Library | Function utilized | Time Used
-------|--------|--------------| ------------------
zcrx.c | linux/kernel.h | /* No functions used  */ | 0
| | linux/errno.h | -EINVAL | 1
| | linux/errno.h | -ENOMEM | 4
| | linux/errno.h | -ENODEV | 1
| | linux/errno.h | -EOPNOTSUPP | 2
| | linux/errno.h | -EFAULT | 3
| | linux/errno.h | -EAGAIN | 2
| | linux/errno.h | -ENOSPC | 1
| | linux/errno.h | -EPROTONOSUPPORT | 1
| | linux/dma-map-ops.h | dma_map_page_attrs | 1
| | linux/dma-map-ops.h | dma_mapping_error | 1
| | linux/dma-map-ops.h | dma_unmap_page_attrs | 2
| | linux/dma-map-ops.h | dma_dev_need_sync | 1
| | linux/dma-map-ops.h | __dma_sync_single_for_device | 1
| | linux/mm.h | /* No functions used  */ | 0
| | linux/nospec.h | array_index_nospec | 1
| | linux/io_uring.h | /* No functions used  */ | 0
| | linux/netdevice.h | netdev_get_by_index | 1
| | linux/netdevice.h | netdev_put | 2
| | linux/rtnetlink.h | /* No functions used  */ | 0
| | linux/skbuff_ref.h | /* No functions used  */ | 0
| | net/page_pool/helpers.h | page_pool_get_dma_addr_netmem | 1
| | net/page_pool/helpers.h | netmem_is_net_iov | 1
| | net/page_pool/helpers.h | netmem_to_net_iov | 2
| | net/page_pool/helpers.h | net_mp_netmem_place_in_cache | 2
| | net/page_pool/helpers.h | page_pool_put_unrefed_netmem | 1
| | net/page_pool/helpers.h | page_pool_unref_netmem | 1
| | net/page_pool/helpers.h | page_pool_fragment_netmem | 1
| | net/page_pool/helpers.h | net_mp_niov_set_dma_addr | 2
| | net/page_pool/helpers.h | net_mp_niov_clear_page_pool | 1
| | net/page_pool/helpers.h | net_mp_niov_set_page_pool | 1
| | net/page_pool/memory_provider.h | /* No functions used  */ | 0
| | net/netlink.h | /* No functions used  */ | 0
| | net/netdev_rx_queue.h | net_mp_open_rxq | 1
| | net/netdev_rx_queue.h | net_mp_close_rxq | 1
| | net/tcp.h | tcp_read_sock | 1
| | net/rps.h | sock_rps_record_flow | 1
| | trace/events/page_pool.h | /* No functions used  */ | 0
| | uapi/linux/io_uring.h | /* No functions used  */ | 0
| | io_uring.h | io_create_region_mmap_safe | 1
| | io_uring.h | io_region_get_ptr | 1
| | io_uring.h | io_free_region | 1
| | io_uring.h | io_kiocb_to_cmd | 6
| | io_uring.h | io_pin_pages | 1
| | io_uring.h | io_buffer_validate | 1
| | io_uring.h | io_uring_alloc_async_data | 0
| | io_uring.h | io_defer_get_uncommited_cqe | 1
| | io_uring.h | io_req_task_work_add | 0
| | io_uring.h | io_req_complete | 0
| | io_uring.h | io_req_set_res | 0
| | io_uring.h | io_req_flags_set | 0
| | io_uring.h | io_req_flags_clear | 0
| | io_uring.h | io_rsrc_add_file | 0
| | io_uring.h | io_rsrc_drop_file | 0
| | io_uring.h | io_add_dr_rsrc | 0
| | io_uring.h | io_sub_dr_rsrc | 0
| | io_uring.h | io_get_rsrc_node | 0
| | io_uring.h | io_put_rsrc_node | 0
| | io_uring.h | io_wait_for_dr_rsrc_free | 0
| | io_uring.h | io_rsrc_cancel_wait | 0
| | io_uring.h | io_install_fixed_file | 0
| | io_uring.h | io_remove_fixed_file | 0
| | kbuf.h | /* No functions used  */ | 0
| | memmap.h | /* No functions used  */ | 0
| | zcrx.h | /* No functions used  */ | 0
| | rsrc.h | /* No functions used  */ | 0
| | unistd.h | /* No functions used  */ | 0
| | linux/slab.h | kzalloc | 4
| | linux/slab.h | kfree | 2
| | linux/slab.h | kvfree | 3
| | linux/slab.h | kvmalloc_array | 4
| | linux/string.h | memchr_inv | 1
| | linux/string.h | memcpy | 1
| | linux/gfp.h | /* No functions used  */ | 0
| | linux/mm.h | get_user_pages_fast | 0
| | linux/mm.h |  unpin_user_pages | 1
| | linux/mm.h | kmap_local_page | 2
| | linux/mm.h | kunmap_local | 2
| | linux/spinlock.h | spin_lock_init | 3
| | linux/spinlock.h | spin_lock | 2
| | linux/spinlock.h | spin_unlock | 2
| | linux/spinlock.h | spin_lock_bh | 3
| | linux/spinlock.h | spin_unlock_bh | 3
| | linux/atomic.h | atomic_set | 1
| | linux/atomic.h | atomic_read | 2
| | linux/atomic.h | atomic_inc | 0
| | linux/atomic.h | atomic_dec | 0
| | linux/atomic.h | atomic_xchg | 1
| | linux/wait.h | /* No functions used  */ | 0
| | linux/device.h | get_device | 1
| | linux/device.h | put_device | 1
| | net/sock.h | lock_sock | 1
| | net/sock.h | release_sock | 1
| | net/sock.h | sock_flag | 2
| | net/sock.h | sock_error | 1
| | net/skbuff.h | skb_headlen | 2
| | net/skbuff.h | skb_shinfo | 1
| | net/skbuff.h | skb_frag_size | 1
| | net/skbuff.h | skb_frag_page | 1
| | net/skbuff.h | skb_frag_off | 2
| | net/skbuff.h | skb_frag_is_net_iov | 1
| | net/skbuff.h | skb_walk_frags | 1
| | asm/uaccess.h | copy_from_user | 2
| | asm/uaccess.h | copy_to_user | 3
| | linux/bug.h | WARN_ON_ONCE | 7
| | linux/bug.h | WARN_ON | 2
| | linux/bitfield.h | roundup_pow_of_two | 1
| | linux/percpu-refcount.h | percpu_ref_get | 1
| | linux/percpu-refcount.h | percpu_ref_put | 1
advise.h | advise.h | io_madvise_prep | 1  
| | advise.h | io_madvise | 1  
| | advise.h | io_fadvise_prep | 1  
| | advise.h | io_fadvise | 1  
cancel.h | cancel.h | io_async_cancel_prep | 1
| | cancel.h | io_async_cancel | 1
| | cancel.h | io_try_cancel | 1
| | cancel.h | io_sync_cancel | 1
| | cancel.h | io_cancel_req_match | 1
| | cancel.h | io_cancel_remove_all | 1
| | cancel.h | io_cancel_remove | 1
| | cancel.h | io_cancel_match_sequence | 1
epoll.h | epoll.h | io_epoll_ctl_prep | 1
| | epoll.h | io_epoll_ctl | 1
| | epoll.h | io_epoll_wait_prep | 1
| | epoll.h | io_epoll_wait | 1
| eventfd.h | /include/linux/io\_uring.h        | io\_eventfd\_register              | 1         |
| | /include/linux/io\_uring.h        | io\_eventfd\_unregister            | 1         |
| | /include/linux/io\_uring.h        | io\_eventfd\_flush\_signal         | 1         |
| | /include/linux/io\_uring.h        | io\_eventfd\_signal                | 1         |
| fdinfo.h | /include/linux/io\_uring.h        | io\_uring\_show\_fdinfo            | 1         |
| filetable.h | /include/linux/io\_uring\_types.h | io\_alloc\_file\_tables            | 1         |
| | /include/linux/io\_uring\_types.h | io\_free\_file\_tables             | 1         |
| | /include/linux/io\_uring\_types.h | io\_fixed\_fd\_install             | 1         |
| | /include/linux/io\_uring\_types.h | \_\_io\_fixed\_fd\_install         | 1         |
| | /include/linux/io\_uring\_types.h | io\_fixed\_fd\_remove              | 1         |
| | /include/linux/io\_uring\_types.h | io\_register\_file\_alloc\_range   | 1         |
| | /include/linux/io\_uring\_types.h | io\_file\_get\_flags               | 1         |
| | /include/linux/io\_uring\_types.h | io\_file\_bitmap\_clear            | 1         |
| | /include/linux/io\_uring\_types.h | io\_file\_bitmap\_set              | 1         |
| | /include/linux/io\_uring\_types.h | io\_slot\_flags                    | 1         |
| | /include/linux/io\_uring\_types.h | io\_slot\_file                     | 1         |
| | /include/linux/io\_uring\_types.h | io\_fixed\_file\_set               | 1         |
| | /include/linux/io\_uring\_types.h | io\_file\_table\_set\_alloc\_range | 1         |
| fs.h | /include/linux/fs.h               | io\_renameat\_prep                 | 1         |
| | /include/linux/fs.h               | io\_renameat                       | 1         |
| | /include/linux/fs.h               | io\_renameat\_cleanup              | 1         |
| | /include/linux/fs.h               | io\_unlinkat\_prep                 | 1         |
| | /include/linux/fs.h               | io\_unlinkat                       | 1         |
| | /include/linux/fs.h               | io\_unlinkat\_cleanup              | 1         |
| | /include/linux/fs.h               | io\_mkdirat\_prep                  | 1         |
| | /include/linux/fs.h               | io\_mkdirat                        | 1         |
| | /include/linux/fs.h               | io\_mkdirat\_cleanup               | 1         |
| | /include/linux/fs.h               | io\_symlinkat\_prep                | 1         |
| | /include/linux/fs.h               | io\_symlinkat                      | 1         |
| | /include/linux/fs.h               | io\_linkat\_prep                   | 1         |
| | /include/linux/fs.h               | io\_linkat                         | 1         |
| | /include/linux/fs.h               | io\_link\_cleanup                  | 1         |
| futex.h | /include/linux/cancel.h           | io\_futex\_prep                    | 1         |
| | /include/linux/cancel.h           | io\_futexv\_prep                   | 1         |
| | /include/linux/cancel.h           | io\_futex\_wait                    | 1         |
| | /include/linux/cancel.h           | io\_futexv\_wait                   | 1         |
| | /include/linux/cancel.h           | io\_futex\_wake                    | 1         |
| | /include/linux/cancel.h           | io\_futex\_cancel                  | 1         |
| | /include/linux/cancel.h           | io\_futex\_remove\_all             | 1         |
| | /include/linux/cancel.h           | io\_futex\_cache\_init             | 1         |
| | /include/linux/cancel.h           | io\_futex\_cache\_free             | 1         |
 io\_uring.h    | linux/hrtimer.h                   | hrtimer\_cancel                  | 1         |
| | linux/hrtimer.h                   | hrtimer\_start\_range\_ns        | 1         |
| | linux/kernel.h                    | WARN\_ON\_ONCE                   | 1         |
| | linux/lockdep.h                   | lockdep\_assert\_held            | 1         |
| io-wq.h     | linux/refcount.h         | refcount\_dec\_and\_test       | 1         |
|             | linux/mm/slub.c          | kfree                          | 1         |
|             | internal/io-wq.h         | io\_wq\_put\_hash              | 1         |
|             | internal/io-wq.h         | io\_wq\_create                 | 1         |
|             | internal/io-wq.h         | io\_wq\_exit\_start            | 1         |
|             | internal/io-wq.h         | io\_wq\_put\_and\_exit         | 1         |
|             | internal/io-wq.h         | io\_wq\_enqueue                | 1         |
|             | internal/io-wq.h         | io\_wq\_hash\_work             | 1         |
|             | internal/io-wq.h         | io\_wq\_cpu\_affinity          | 1         |
|             | internal/io-wq.h         | io\_wq\_max\_workers           | 1         |
|             | internal/io-wq.h         | io\_wq\_worker\_stopped        | 1         |
|             | internal/io-wq.h         | io\_wq\_is\_hashed             | 1         |
|             | internal/io-wq.h         | io\_wq\_cancel\_cb             | 1         |
|             | linux/sched.h            | current->flags                 | 1         |
| kbuf.h      | linux/io\_uring\_types.h | struct io\_kiocb               | 1         |
|             | linux/uio.h              | struct iovec                   | 1         |
|             | iou/kbuf.h               | io\_buffer\_select             | 1         |
|             | iou/kbuf.h               | io\_buffers\_select            | 1         |
|             | iou/kbuf.h               | io\_buffers\_peek              | 1         |
|             | iou/kbuf.h               | io\_destroy\_buffers           | 1         |
|             | iou/kbuf.h               | io\_remove\_buffers\_prep      | 1         |
|             | iou/kbuf.h               | io\_remove\_buffers            | 1         |
|             | iou/kbuf.h               | io\_provide\_buffers\_prep     | 1         |
|             | iou/kbuf.h               | io\_provide\_buffers           | 1         |
|             | iou/kbuf.h               | io\_register\_pbuf\_ring       | 1         |
|             | iou/kbuf.h               | io\_unregister\_pbuf\_ring     | 1         |
|             | iou/kbuf.h               | io\_register\_pbuf\_status     | 1         |
|             | iou/kbuf.h               | io\_kbuf\_recycle\_legacy      | 1         |
|             | iou/kbuf.h               | io\_kbuf\_drop\_legacy         | 1         |
|             | iou/kbuf.h               | \_\_io\_put\_kbufs             | 1         |
|             | iou/kbuf.h               | io\_kbuf\_commit               | 1         |
|             | iou/kbuf.h               | io\_pbuf\_get\_region          | 1         |
|             | iou/kbuf.h               | io\_kbuf\_recycle\_ring        | 1         |
|             | iou/kbuf.h               | io\_do\_buffer\_select         | 1         |
|             | iou/kbuf.h               | io\_kbuf\_recycle              | 1         |
|             | iou/kbuf.h               | io\_put\_kbuf                  | 1         |
|             | iou/kbuf.h               | io\_put\_kbufs                 | 1         |
| memmap.h    | linux/mm.h               | vm\_area\_struct               | 1         |
|             | iou/memmap.h             | io\_uring\_get\_unmapped\_area | 1         |
|             | iou/memmap.h             | io\_uring\_mmap                | 1         |
|             | iou/memmap.h             | io\_free\_region               | 1         |
|             | iou/memmap.h             | io\_create\_region             | 1         |
|             | iou/memmap.h             | io\_create\_region\_mmap\_safe | 1         |
|             | iou/memmap.h             | io\_region\_get\_ptr           | 1         |
|             | iou/memmap.h             | io\_region\_is\_set            | 1         |
| msg\_ring.h | linux/io\_uring.h        | struct io\_uring\_sqe          | 1         |
|             | iou/msg\_ring.h          | io\_uring\_sync\_msg\_ring     | 1         |
|             | iou/msg\_ring.h          | io\_msg\_ring\_prep            | 1         |
|             | iou/msg\_ring.h          | io\_msg\_ring                  | 1         |
|             | iou/msg\_ring.h          | io\_msg\_ring\_cleanup         | 1         |
| napi.h      | net/busy\_poll.h         | napi\_id                       | 1         |
|             | iou/napi.h               | io\_napi\_init                 | 1         |
|             | iou/napi.h               | io\_napi\_free                 | 1         |
|             | iou/napi.h               | io\_register\_napi             | 1         |
|             | iou/napi.h               | io\_unregister\_napi           | 1         |
|             | iou/napi.h               | \_\_io\_napi\_add\_id          | 1         |
|             | iou/napi.h               | \_\_io\_napi\_busy\_loop       | 1         |
|             | iou/napi.h               | io\_napi\_sqpoll\_busy\_poll   | 1         |
|             | iou/napi.h               | io\_napi                       | 1         |
|             | iou/napi.h               | io\_napi\_busy\_loop           | 1         |
|             | iou/napi.h               | io\_napi\_add                  | 1         || | linux/slab.h                      | kfree                            | 1         |
| | linux/slab.h                      | kmalloc                          | 1         |
| | linux/spinlock.h                  | spin\_lock                       | 1         |
| | linux/spinlock.h                  | spin\_unlock                     | 1         |
| | linux/wait.h                      | finish\_wait                     | 1         |
| | linux/wait.h                      | prepare\_to\_wait                | 1         |
| net.h | linux/net.h              | struct sockaddr                             | 1         |
|             | linux/uio.h              | struct iovec                                | 1         |
|             | linux/io\_uring\_types.h | struct io\_kiocb                            | 1         |
|             | io\_uring/net.h          | io\_shutdown\_prep                          | 1         |
|             |                          | io\_shutdown                                | 1         |
|             |                          | io\_sendmsg\_recvmsg\_cleanup               | 1         |
|             |                          | io\_sendmsg\_prep                           | 1         |
|             |                          | io\_sendmsg                                 | 1         |
|             |                          | io\_send                                    | 1         |
|             |                          | io\_recvmsg\_prep                           | 1         |
|             |                          | io\_recvmsg                                 | 1         |
|             |                          | io\_recv                                    | 1         |
|             |                          | io\_sendrecv\_fail                          | 1         |
|             |                          | io\_accept\_prep                            | 1         |
|             |                          | io\_accept                                  | 1         |
|             |                          | io\_socket\_prep                            | 1         |
|             |                          | io\_socket                                  | 1         |
|             |                          | io\_connect\_prep                           | 1         |
|             |                          | io\_connect                                 | 1         |
|             |                          | io\_send\_zc                                | 1         |
|             |                          | io\_sendmsg\_zc                             | 1         |
|             |                          | io\_send\_zc\_prep                          | 1         |
|             |                          | io\_send\_zc\_cleanup                       | 1         |
|             |                          | io\_bind\_prep                              | 1         |
|             |                          | io\_bind                                    | 1         |
|             |                          | io\_listen\_prep                            | 1         |
|             |                          | io\_listen                                  | 1         |
|             |                          | io\_netmsg\_cache\_free                     | 1         |
| nop.h   | io\_uring/nop.h          | io\_nop\_prep                               | 1         |
|             |                          | io\_nop                                     | 1         |
| notif.h | linux/net.h              | struct sock                                 | 1         |
|             | linux/uio.h              | struct iovec                                | 1         |
|             | net/sock.h               | struct sk\_buff                             | 1         |
|             | linux/nospec.h           | barrier macros (e.g., array\_index\_nospec) | 1         |
|             | io\_uring/notif.h        | io\_alloc\_notif                            | 1         |
|             |                          | io\_tx\_ubuf\_complete                      | 1         |
|             |                          | io\_notif\_to\_data                         | 1         |
|             |                          | io\_notif\_flush                            | 1         |
|             |                          | io\_notif\_account\_mem                     | 1         |
| opdef.h | io\_uring/opdef.h        | struct io\_issue\_def                       | 1         |
|             |                          | struct io\_cold\_def                        | 1         |
|             |                          | io\_uring\_op\_supported                    | 1         |
|             |                          | io\_uring\_optable\_init                    | 1         |
|             |                          | io\_issue\_defs                             | 1         |
|             |                          | io\_cold\_defs                              | 1         |
| openclose.h | io\uring/openclose.h    | \\_io\_close\_fixed         | 1         |
|                 |                          | io\_openat\_prep             | 1         |
|                 |                          | io\_openat                   | 1         |
|                 |                          | io\_open\_cleanup            | 1         |
|                 |                          | io\_openat2\_prep            | 1         |
|                 |                          | io\_openat2                  | 1         |
|                 |                          | io\_close\_prep              | 1         |
|                 |                          | io\_close                    | 1         |
|                 |                          | io\_install\_fixed\_fd\_prep | 1         |
|                 |                          | io\_install\_fixed\_fd       | 1         |
| poll.h      | linux/io\_uring\_types.h | struct io\_kiocb             | 1         |
|                 | io\_uring/poll.h         | struct io\_poll              | 1         |
|                 |                          | struct async\_poll           | 1         |
|                 |                          | io\_poll\_multishot\_retry   | 1         |
|                 |                          | io\_poll\_add\_prep          | 1         |
|                 |                          | io\_poll\_add                | 1         |
|                 |                          | io\_poll\_remove\_prep       | 1         |
|                 |                          | io\_poll\_remove             | 1         |
|                 |                          | io\_poll\_cancel             | 1         |
|                 |                          | io\_arm\_poll\_handler       | 1         |
|                 |                          | io\_poll\_remove\_all        | 1         |
|                 |                          | io\_poll\_task\_func         | 1         |
| refs.h     | linux/io\_uring\_types.h | req\_ref\_zero\_or\_close\_to\_overflow | 1         |
|                |                          | req\_ref\_inc\_not\_zero                | 1         |
|                |                          | req\_ref\_put\_and\_test\_atomic        | 1         |
|                |                          | req\_ref\_put\_and\_test                | 1         |
|                |                          | req\_ref\_get                           | 1         |
|                |                          | req\_ref\_put                           | 1         |
|                |                          | \_\_io\_req\_set\_refcount              | 1         |
|                |                          | io\_req\_set\_refcount                  | 1         |
| register.h | io\_uring/register.h     | io\_eventfd\_unregister                 | 1         |
|                |                          | io\_unregister\_personality             | 1         |
|                |                          | io\_uring\_register\_get\_file          | 1         |
| rsrc.h    | io\_uring/rsrc.h         | io\_rsrc\_cache\_init                   | 1         |
|                |                          | io\_rsrc\_cache\_free                   | 1         |
|                |                          | io\_rsrc\_node\_alloc                   | 1         |
|                |                          | io\_free\_rsrc\_node                    | 1         |
|                |                          | io\_rsrc\_data\_free                    | 1         |
|                |                          | io\_rsrc\_data\_alloc                   | 1         |
|                |                          | io\_find\_buf\_node                     | 1         |
|                |                          | io\_import\_reg\_buf                    | 1         |
|                |                          | io\_import\_reg\_vec                    | 1         |
|                |                          | io\_prep\_reg\_iovec                    | 1         |
|                |                          | io\_register\_clone\_buffers            | 1         |
|                |                          | io\_sqe\_buffers\_unregister            | 1         |
|                |                          | io\_sqe\_buffers\_register              | 1         |
|                |                          | io\_sqe\_files\_unregister              | 1         |
|                |                          | io\_sqe\_files\_register                | 1         |
|                |                          | io\_register\_files\_update             | 1         |
|                |                          | io\_register\_rsrc\_update              | 1         |
|                |                          | io\_register\_rsrc                      | 1         |
|                |                          | io\_buffer\_validate                    | 1         |
|                |                          | io\_check\_coalesce\_buffer             | 1         |
|                |                          | io\_rsrc\_node\_lookup                  | 1         |
|                |                          | io\_put\_rsrc\_node                     | 1         |
|                |                          | io\_reset\_rsrc\_node                   | 1         |
|                |                          | io\_req\_put\_rsrc\_nodes               | 1         |
|                |                          | io\_req\_assign\_rsrc\_node             | 1         |
|                |                          | io\_req\_assign\_buf\_node              | 1         |
|                |                          | io\_files\_update                       | 1         |
|                |                          | io\_files\_update\_prep                 | 1         |
|                |                          | \_\_io\_account\_mem                    | 1         |
|                |                          | \_\_io\_unaccount\_mem                  | 1         |
|                |                          | io\_vec\_free                           | 1         |
|                |                          | io\_vec\_realloc                        | 1         |
|                |                          | io\_vec\_reset\_iovec                   | 1         |
|                |                          | io\_alloc\_cache\_vec\_kasan            | 1         |
| rw\.h  | linux/io\_uring\_types.h | io\_prep\_read\_fixed      | 1         |
|             |                          | io\_prep\_write\_fixed     | 1         |
|             |                          | io\_prep\_readv\_fixed     | 1         |
|             |                          | io\_prep\_writev\_fixed    | 1         |
|             |                          | io\_prep\_readv            | 1         |
|             |                          | io\_prep\_writev           | 1         |
|             |                          | io\_prep\_read             | 1         |
|             |                          | io\_prep\_write            | 1         |
|             |                          | io\_read                   | 1         |
|             |                          | io\_write                  | 1         |
|             |                          | io\_read\_fixed            | 1         |
|             |                          | io\_write\_fixed           | 1         |
|             |                          | io\_readv\_writev\_cleanup | 1         |
|             |                          | io\_rw\_fail               | 1         |
|             |                          | io\_req\_rw\_complete      | 1         |
|             |                          | io\_read\_mshot\_prep      | 1         |
|             |                          | io\_read\_mshot            | 1         |
|             |                          | io\_rw\_cache\_free        | 1         |
| slist.h | linux/io\_uring\_types.h | wq\_list\_add\_after       | 1         |
|             |                          | wq\_list\_add\_tail        | 1         |
|             |                          | wq\_list\_add\_head        | 1         |
|             |                          | wq\_list\_cut              | 1         |
|             |                          | \_\_wq\_list\_splice       | 1         |
|             |                          | wq\_list\_splice           | 1         |
|             |                          | wq\_stack\_add\_head       | 1         |
|             |                          | wq\_list\_del              | 1         |
|             |                          | wq\_stack\_extract         | 1         |
|             |                          | wq\_next\_work             | 1         |
| splice.h  | -       | io\_tee\_prep                                | 1         |
|               |         | io\_tee                                      | 1         |
|               |         | io\_splice\_cleanup                          | 1         |
|               |         | io\_splice\_prep                             | 1         |
|               |         | io\_splice                                   | 1         |
| sqpoll.h  | -       | io\_sq\_offload\_create                      | 1         |
|               |         | io\_sq\_thread\_finish                       | 1         |
|               |         | io\_sq\_thread\_stop                         | 1         |
|               |         | io\_sq\_thread\_park                         | 1         |
|               |         | io\_sq\_thread\_unpark                       | 1         |
|               |         | io\_put\_sq\_data                            | 1         |
|               |         | io\_sqpoll\_wait\_sq                         | 1         |
|               |         | io\_sqpoll\_wq\_cpu\_affinity                | 1         |
| statx.h   | -       | io\_statx\_prep                              | 1         |
|               |         | io\_statx                                    | 1         |
|               |         | io\_statx\_cleanup                           | 1         |
| sync.h    | -       | io\_sfr\_prep                                | 1         |
|               |         | io\_sync\_file\_range                        | 1         |
|               |         | io\_fsync\_prep                              | 1         |
|               |         | io\_fsync                                    | 1         |
|               |         | io\_fallocate\_prep                          | 1         |
|               |         | io\_fallocate                                | 1         |
| tctx.h    | -       | io\_uring\_alloc\_task\_context              | 1         |
|               |         | io\_uring\_del\_tctx\_node                   | 1         |
|               |         | \_\_io\_uring\_add\_tctx\_node               | 1         |
|               |         | \_\_io\_uring\_add\_tctx\_node\_from\_submit | 1         |
|               |         | io\_uring\_clean\_tctx                       | 1         |
|               |         | io\_uring\_unreg\_ringfd                     | 1         |
|               |         | io\_ringfd\_register                         | 1         |
|               |         | io\_ringfd\_unregister                       | 1         |
|               |         | io\_uring\_add\_tctx\_node (inline)          | 1         |
| timeout.h | -       | \_\_io\_disarm\_linked\_timeout              | 1         |
|               |         | io\_disarm\_linked\_timeout (inline)         | 1         |
|               |         | io\_flush\_timeouts                          | 1         |
|               |         | io\_timeout\_cancel                          | 1         |
|               |         | io\_kill\_timeouts                           | 1         |
|               |         | io\_queue\_linked\_timeout                   | 1         |
|               |         | io\_disarm\_next                             | 1         |
|               |         | io\_timeout\_prep                            | 1         |
|               |         | io\_link\_timeout\_prep                      | 1         |
|               |         | io\_timeout                                  | 1         |
|               |         | io\_timeout\_remove\_prep                    | 1         |
|               |         | io\_timeout\_remove                          | 1         |
| truncate.h | -                          | io_ftruncate_prep                                 | 1         |
|                |                            | io_ftruncate                                      | 1         |
| uring_cmd.h | -                          | io_uring_cmd                                      | 1         |
|                |                            | io_uring_cmd_prep                                 | 1         |
|                |                            | io_uring_cmd_cleanup                              | 1         |
|                |                            | io_uring_try_cancel_uring_cmd                     | 1         |
|                |                            | io_cmd_cache_free                                 | 1         |
|                |                            | io_uring_cmd_import_fixed_vec                     | 1         |
| waitid.h   | -                          | io_waitid_prep                                    | 1         |
|                |                            | io_waitid                                         | 1         |
|                |                            | io_waitid_cancel                                  | 1         |
|                |                            | io_waitid_remove_all                              | 1         |
| xattr.h   | -                          | io_xattr_cleanup                                  | 1         |
|                |                            | io_fsetxattr_prep                                 | 1         |
|                |                            | io_fsetxattr                                      | 1         |
|                |                            | io_setxattr_prep                                  | 1         |
|                |                            | io_setxattr                                       | 1         |
|                |                            | io_fgetxattr_prep                                 | 1         |
|                |                            | io_fgetxattr                                      | 1         |
|                |                            | io_getxattr_prep                                  | 1         |
|                |                            | io_getxattr                                       | 1         |
| zcrx.h     | -                          | io_register_zcrx_ifq                              | 1         |
|                |                            | io_unregister_zcrx_ifqs                           | 1         |
|                |                            | io_shutdown_zcrx_ifqs                            | 1         |
|                |                            | io_zcrx_recv                                      | 1         |
|                |                            | io_recvzc                                         | 1         |
|                |                            | io_recvzc_prep                                    | 1         |


