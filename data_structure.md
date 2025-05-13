# Task 3: Data Structure Investigation
The objective of this task is to document all internal data structures defined in io_uring. 

Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_ev_fd       | io_uring/eventfd.c | eventfd_ctx, uint, uint, refcount_t, atomic_t, rcu_head | io_eventfd_free | io_uring/eventfd.c | local variable
| | | | io_eventfd_put | io_uring/eventfd.c | function parameter
| | | | io_eventfd_do_signal | io_uring/eventfd.c | local variable, function parameter
| | | | __io_eventfd_signal | io_uring/eventfd.c | function parameter
| | | | io_eventfd_grab | io_uring/eventfd.c | return value, local variable
| | | | io_eventfd_signal | io_uring/eventfd.c | local variable 
| | | | io_eventfd_flush_signal | io_uring/eventfd.c | local variable
| | | | io_eventfd_register | io_uring/eventfd.c | local variable
| | | | io_eventfd_unregister | io_uring/eventfd.c | function parameter

If the following row value in a column is missing, assume the value is the same with the previous row in the same column. 
Continue until all data structures documented properly.

### memmap.c
Structure name | Defined in | Attributes | Caller Functions Source | Source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_mapped_region | memmap.h | struct page \**, void \*, unsigned long, unsigned int, unsigned long | io_free_region | memmap.c | function parameter
| | | | io_region_init_ptr | memmap.c | function parameter
| | | | io_region_pin_pages | memmap.c | function parameter
| | | | io_region_allocate_pages | memmap.c | function parameter
| | | | io_create_region | memmap.c | function parameter, local variable
| | | | io_create_region_mmap_safe | memmap.c | function parameter, local variable
| | | | io_mmap_get_region | memmap.c | function parameter, local variable
| | | | io_region_validate_mmap | memmap.c | function parameter
| | | | io_uring_validate_mmap_request | memmap.c | local variable
| | | | io_region_mmap | memmap.c | function parameter
io_uring_region_desc | linux/io_uring_types.h | u64, u64, u32, u32, u64, u64, __u64[3] | io_allocate_rbuf_ring | io_uring.c | function parameter
| | | | io_create_region | memmap.c | function parameter
| | | | io_create_region_mmap_safe | memmap.c | function parameter

### memmap.h
Structure name | Defined in | Attributes | Caller Functions Source | Source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_mapped_region | memmap.h | struct page \**, void \*, unsigned long, unsigned int, unsigned long | io_free_region | memmap.c | function parameter
| | |  | io_create_region | memmap.c | function parameter
| | |  | io_create_region_mmap_safe | memmap.c | function parameter

### msg_ring.c
Structure name | Defined in | Attributes | Caller Functions Source | Source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_msg | msg_ring.h | struct file \*, struct file \*, struct callback_head, u64, u32, u32, u32, union{u32, u32}, u32 | io_msg_ring_cleanup | msg_ring.c | function parameter, local variable
|  |  |  | io_msg_need_remote | msg_ring.c | function parameter
|  |  |  | io_msg_data_remote | msg_ring.c | function parameter
|  |  |  | __io_msg_ring_data | msg_ring.c | function parameter
|  |  |  | io_msg_ring_data | msg_ring.c | function parameter
|  |  |  | io_msg_grab_file | msg_ring.c | function parameter
|  |  |  | io_msg_install_complete | msg_ring.c | function parameter
|  |  |  | io_msg_tw_fd_complete | msg_ring.c | local variable, function parameter
|  |  |  | io_msg_fd_remote | msg_ring.c | function parameter
|  |  |  | io_msg_send_fd | msg_ring.c | function parameter
|  |  |  | __io_msg_ring_prep | msg_ring.c | function parameter, local variable
|  |  |  | io_msg_ring_prep | msg_ring.c | function parameter
|  |  |  | io_msg_ring | msg_ring.c | function parameter
|  |  |  | io_uring_sync_msg_ring | msg_ring.c | local variable

### msg_ring.h
Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_msg         | io_uring/msg_ring.c | src_file, user_data, len, cmd, src_fd, dst_fd, flags, cqe_flags | io_msg_ring_prep | io_uring/msg_ring.c | local variable
| | | io_msg_ring | io_uring/msg_ring.c | local variable
| | | io_msg_ring_cleanup | io_uring/msg_ring.c | local variable
| | | io_msg_data_remote | io_uring/msg_ring.c | function parameter
| | | __io_msg_ring_data | io_uring/msg_ring.c | function parameter
| | | io_msg_grab_file | io_uring/msg_ring.c | local variable
| | | io_msg_install_complete | io_uring/msg_ring.c | local variable

### napi.c
Structure name | Defined in | Attributes | Caller Functions Source | Source Caller | Usage
---------------|------------|------------|--------------------------|----------------|-------
io_napi_entry | io_uring/napi.c | unsigned int napi_id, struct list_head list, unsigned long timeout, struct hlist_node node, struct rcu_head rcu | io_napi_hash_find | io_uring/napi.c | local variable
| | | __io_napi_add_id | io_uring/napi.c | local variable, allocated with kmalloc
| | | __io_napi_del_id | io_uring/napi.c | local variable
| | | __io_napi_remove_stale | io_uring/napi.c | loop iterator (list_for_each_entry)
| | | static_tracking_do_busy_loop | io_uring/napi.c | loop iterator (list_for_each_entry_rcu)
| | | dynamic_tracking_do_busy_loop | io_uring/napi.c | loop iterator (list_for_each_entry_rcu)
| | | io_napi_free | io_uring/napi.c | loop iterator (list_for_each_entry)

### napi.h
Structure name | Defined in | Attributes | Caller Functions Source | Source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_ring_ctx |From io_uring.h (included in napi.h) | Refer to io_uring.h for attributes | io_napi_init | napi.c | function parameter
| | | | io_napi_free | napi.c | function parameter
| | | | io_register_napi | napi.c | function parameter
| | | | io_unregister_napi | napi.c | function parameter
| | | | __io_napi_add_id | napi.c | function parameter
| | | | __io_napi_busy_loop | napi.c | function parameter
| | | | io_napi_sqpoll_busy_poll | napi.c | function parameter
| | |  | io_napi | napi.c | function parameter
| | |  | io_napi_busy_loop | napi.c | function parameter
|io_kiocb|From io_uring.h (included in napi.h)|Refer to io_uring.h for attributes|io_napi_add|napi.c|function parameter

### net.c
Structure name | Defined in | Attributes | Caller Functions Source | Source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_shutdown | net.c | struct file \*, int | io_shutdown_prep | net.c | local variable
| | | | io_shutdown | net.c | local variable, function parameter
io_accept | net.c | struct file \*, struct sockaddr __user \*, int __user \*, int, int, u32, unsigned long | (None) | (None) | (Not directly used as a variable in the provided code, but its members are accessed via `io_kiocb_to_cmd`)
io_socket | net.c | struct file \*, int, int, int, int, u32, unsigned long | (None) | (None) | (Not directly used as a variable, but its members are accessed)
io_connect|net.c|struct file *,struct sockaddr __user *, int, bool, bool|(None)|(None)|(Not directly used as variable)
io_bind | net.c | struct file \*, int | (None) | (None) | (Not directly used as a variable)
io_listen | net.c | struct file \*, int | (None) | (None) | (Not directly used as a variable)
io_sr_msg | net.c | struct file \*, union {...}, int, unsigned, unsigned, u16, bool, void __user \*, struct io_kiocb \* | io_sendmsg_prep | net.c | local variable
|  |  |  | io_sendmsg | net.c | local variable
|  |  |  | io_send_setup | net.c | local variable
|  |  |  | io_recvmsg_prep | net.c | local variable
|  |  |  | io_recv_finish | net.c | function parameter
|  |  |  | io_recvmsg | net.c | local variable
io_recvzc | net.c | struct file \*, unsigned, u16, u32, struct io_zcrx_ifq \* | (None) | (None) | (Not directly used as a variable)
io_async_msghdr| io_uring.h | struct iovec \*, struct kvec, struct sockaddr_storage, struct msghdr, struct iovec, int, int, void __user\*, u32 | io_sendmsg_setup | net.c | local variable
||||io_sendmsg|net.c|function parameter, local variable
||||io_recvmsg_prep|net.c|local variable
||||io_recv_finish|net.c|function parameter
||||io_recvmsg|net.c|local variable

### net.h
Structure name | Defined in | Attributes | Caller Functions Source | Source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_async_msghdr | net.h | struct iou_vec, int, struct iovec, __kernel_size_t, __kernel_size_t, struct sockaddr __user \*, struct msghdr, struct sockaddr_storage | io_sendmsg_setup | net.c | local variable
||||io_sendmsg|net.c|function parameter, local variable
||||io_recvmsg_prep|net.c|local variable
||||io_recv_finish|net.c|function parameter
||||io_recvmsg|net.c|local variable

### nop.c
Structure name | Defined in | Attributes | Caller Functions Source | Source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_nop | nop.h | struct file \*, int, int, unsigned int | io_nop_prep | nop.c | local variable
||||io_nop|nop.c|local variable

### nop.h
Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_kiocb       | io_uring/nop.h | ctx, file (assumed from other contexts) | io_nop_prep | io_uring/nop.h | function parameter
| | | io_nop | io_uring/nop.h | function parameter
io_uring_sqe   | io_uring/nop.h | opcode, flags, ioprio, fd, off, addr, len (assumed) | io_nop_prep | io_uring/nop.h | function parameter

### notif.c
Structure name | Defined in | Attributes | Caller Functions Source | Source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_notif_data | notif.h | struct file *, struct ubuf_info, struct io_notif_data *, struct io_notif_data *, unsigned, bool, bool, bool | io_notif_to_data | notif.h | Used to get the io_notif_data from a io_kiocb
||||io_notif_flush|notif.h|local variable
||||io_notif_account_mem|notif.h|local variable
||||io_notif_tw_complete|notif.c|local variable, function parameter, used in loop
||||io_tx_ubuf_complete|notif.c|local variable, container_of(uarg)
||||io_link_skb|notif.c|local variable, container_of(uarg), linked via next/head
||||io_alloc_notif|notif.c|local variable, initialized with default values

ubuf_info_ops | notif.c | complete (fn ptr), link_skb (fn ptr) | static const definition | notif.c | statically assigned to uarg.ops

ubuf_info | <linux/net.h> | flags, ops (pointer), refcnt | io_tx_ubuf_complete | notif.c | function parameter, member of io_notif_data
||||io_link_skb|notif.c|function parameter, compared and reassigned

io_kiocb | io_uring.h | opcode, flags, file, tctx, ctx, file_node, buf_node, io_task_work | io_notif_tw_complete | notif.c | function parameter, used in loop
||||io_tx_ubuf_complete|notif.c|local variable, from cmd_to_io_kiocb
||||io_link_skb|notif.c|local variable, from cmd_to_io_kiocb
||||io_alloc_notif|notif.c|return value, local variable

io_ring_ctx | io_uring.h | uring_lock, user | io_alloc_notif | notif.c | function parameter, used for memory check


### notif.h
Structure name | Defined in | Attributes | Caller Functions Source | Source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_notif_data | notif.h | struct file *, struct ubuf_info, struct io_notif_data *, struct io_notif_data *, unsigned, bool, bool, bool | io_notif_to_data | notif.h | Used to get the io_notif_data from a io_kiocb
||||io_notif_flush|notif.h|local variable
||||io_notif_account_mem|notif.h|local variable

### opdef.c
Structure name | Defined in | Attributes | Caller Functions Source | Source Caller | Usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_issue_def | io_uring/opdef.c | audit_skip, iopoll, prep, issue | io_issue_defs (static array init) | io_uring/opdef.c | element values
| | needs_file, unbound_nonreg_file, pollin, buffer_select, plug, audit_skip, ioprio, iopoll, iopoll_queue, vectored, async_size, prep, issue | io_issue_defs[IORING_OP_READV] | io_uring/opdef.c | array index definition
| | needs_file, hash_reg_file, unbound_nonreg_file, pollout, plug, audit_skip, ioprio, iopoll, iopoll_queue, vectored, async_size, prep, issue | io_issue_defs[IORING_OP_WRITEV] | io_uring/opdef.c | array index definition
| | needs_file, audit_skip, prep, issue | io_issue_defs[IORING_OP_FSYNC] | io_uring/opdef.c | array index definition
| | needs_file, unbound_nonreg_file, pollin, plug, audit_skip, ioprio, iopoll, iopoll_queue, async_size, prep, issue | io_issue_defs[IORING_OP_READ_FIXED] | io_uring/opdef.c | array index definition
| | needs_file, hash_reg_file, unbound_nonreg_file, pollout, plug, audit_skip, ioprio, iopoll, iopoll_queue, async_size, prep, issue | io_issue_defs[IORING_OP_WRITE_FIXED] | io_uring/opdef.c | array index definition
| | needs_file, unbound_nonreg_file, audit_skip, prep, issue | io_issue_defs[IORING_OP_POLL_ADD] | io_uring/opdef.c | array index definition
| | audit_skip, prep, issue | io_issue_defs[IORING_OP_POLL_REMOVE] | io_uring/opdef.c | array index definition
| | needs_file, audit_skip, prep, issue | io_issue_defs[IORING_OP_SYNC_FILE_RANGE] | io_uring/opdef.c | array index definition
| | needs_file, unbound_nonreg_file, pollout, ioprio, async_size, prep, issue | io_issue_defs[IORING_OP_SENDMSG] | io_uring/opdef.c | array index definition
| | needs_file, unbound_nonreg_file, pollin, buffer_select, ioprio, async_size, prep, issue | io_issue_defs[IORING_OP_RECVMSG] | io_uring/opdef.c | array index definition
| | audit_skip, async_size, prep, issue | io_issue_defs[IORING_OP_TIMEOUT] | io_uring/opdef.c | array index definition
| | audit_skip, prep, issue | io_issue_defs[IORING_OP_TIMEOUT_REMOVE] | io_uring/opdef.c | array index definition
| | needs_file, unbound_nonreg_file, pollin, poll_exclusive, ioprio, prep, issue | io_issue_defs[IORING_OP_ACCEPT] | io_uring/opdef.c | array index definition
| | audit_skip, prep, issue | io_issue_defs[IORING_OP_ASYNC_CANCEL] | io_uring/opdef.c | array index definition
| | audit_skip, async_size, prep, issue | io_issue_defs[IORING_OP_LINK_TIMEOUT] | io_uring/opdef.c | array index definition
| | needs_file, unbound_nonreg_file, pollout, async_size, prep, issue | io_issue_defs[IORING_OP_CONNECT] | io_uring/opdef.c | array index definition
| | needs_file, prep, issue | io_issue_defs[IORING_OP_FALLOCATE] | io_uring/opdef.c | array index definition
| | prep, issue | io_issue_defs[IORING_OP_OPENAT] | io_uring/opdef.c | array index definition
| | prep, issue | io_issue_defs[IORING_OP_CLOSE] | io_uring/opdef.c | array index definition
| | audit_skip, iopoll, prep, issue | io_issue_defs[IORING_OP_FILES_UPDATE] | io_uring/opdef.c | array index definition
| | audit_skip, prep, issue | io_issue_defs[IORING_OP_STATX] | io_uring/opdef.c | array index definition
| | needs_file, unbound_nonreg_file, pollin, buffer_select, plug, audit_skip, ioprio, iopoll, iopoll_queue, async_size, prep, issue | io_issue_defs[IORING_OP_READ] | io_uring/opdef.c | array index definition
| | needs_file, hash_reg_file, unbound_nonreg_file, pollout, plug, audit_skip, ioprio, iopoll, iopoll_queue, async_size, prep, issue | io_issue_defs[IORING_OP_WRITE] | io_uring/opdef.c | array index definition
| | needs_file, audit_skip, prep, issue | io_issue_defs[IORING_OP_FADVISE] | io_uring/opdef.c | array index definition
| | audit_skip, prep, issue | io_issue_defs[IORING_OP_MADVISE] | io_uring/opdef.c | array index definition
| | needs_file, unbound_nonreg_file, pollout, audit_skip, ioprio, buffer_select, async_size, prep, issue | io_issue_defs[IORING_OP_SEND] | io_uring/opdef.c | array index definition
| | needs_file, unbound_nonreg_file, pollin, buffer_select, audit_skip, ioprio, async_size, prep, issue | io_issue_defs[IORING_OP_RECV] | io_uring/opdef.c | array index definition

### opdef.h
Structure name | Defined in | Attributes | Caller Functions Source | Source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_issue_def | opdef.h | needs_file, plug, ioprio, iopoll, buffer_select, hash_reg_file, unbound_nonreg_file, pollin, pollout, poll_exclusive, audit_skip, iopoll_queue, vectored, async_size, issue, prep | io_uring_optable_init | opdef.c | Array of structures
io_cold_def | opdef.h | name, cleanup, fail | io_uring_get_opcode | opdef.c | Array of structures

### openclose.c
Structure name | Defined in | Attributes | Caller Functions Source | Source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_open | openclose.c | file, dfd, file_slot, filename, how, nofile | __io_openat_prep | openclose.c | local variable
|||| io_openat_prep | openclose.c | local variable
|||| io_openat2_prep | openclose.c | local variable
|||| io_openat2 | openclose.c | local variable
|||| io_open_cleanup | openclose.c | local variable
io_close | openclose.c | file, fd, file_slot | io_close_fixed | openclose.c | local variable
|||| io_close_prep | openclose.c | local variable
|||| io_close | openclose.c | local variable
io_fixed_install | openclose.c | file, o_flags | io_install_fixed_fd_prep | openclose.c | local variable
|||| io_install_fixed_fd | openclose.c | local variable

### openclose.h
Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_kiocb       | io_uring/io_uring.h | opcode, flags, file, tctx, ctx, file_node, buf_node, io_task_work | io_openat_prep | io_uring/openclose.h | function parameter
| | | io_openat | io_uring/openclose.h | function parameter
| | | io_open_cleanup | io_uring/openclose.h | function parameter
| | | io_openat2_prep | io_uring/openclose.h | function parameter
| | | io_openat2 | io_uring/openclose.h | function parameter
| | | io_close_prep | io_uring/openclose.h | function parameter
| | | io_close | io_uring/openclose.h | function parameter
| | | io_install_fixed_fd_prep | io_uring/openclose.h | function parameter
| | | io_install_fixed_fd | io_uring/openclose.h | function parameter
io_ring_ctx    | io_uring/io_uring.h | uring_lock, user | __io_close_fixed | io_uring/openclose.h | function parameter
io_uring_sqe   | include/uapi/linux/io_uring.h | fd, off, addr, len, opcode, flags, user_data, buf_index | io_openat_prep | io_uring/openclose.h | function parameter
| | | io_openat2_prep | io_uring/openclose.h | function parameter
| | | io_close_prep | io_uring/openclose.h | function parameter
| | | io_install_fixed_fd_prep | io_uring/openclose.h | function parameter

### poll.c
Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_poll_update | io_uring/poll.c | struct file \*file, u64 old_user_data, u64 new_user_data, \_\_poll_t events, bool update_events, bool update_user_data | io_poll_remove_prep | io_uring/poll.c | local variable
| | | | io_poll_remove | io_uring/poll.c | local variable
io_poll_table | io_uring/poll.c | struct poll_table_struct pt, struct io_kiocb \*req, int nr_entries, int error, bool owning, \_\_poll_t result_mask | io_poll_queue_proc | io_uring/poll.c | local variable
| | | | io_poll_can_finish_inline | io_uring/poll.c | function parameter
| | | | \_\_io_arm_poll_handler | io_uring/poll.c | local variable
| | | | io_arm_poll_handler | io_uring/poll.c | local variable
| | | | io_poll_add | io_uring/poll.c | local variable
io_poll | io_uring/poll.c | struct wait_queue_head \*head, \_\_poll_t events, struct wait_queue_entry wait | io_poll_get_double | io_uring/poll.c | return value
| | | | io_poll_get_single | io_uring/poll.c | return value
| | | | io_init_poll_iocb | io_uring/poll.c | function parameter
| | | | io_poll_remove_entry | io_uring/poll.c | function parameter
| | | | \_\_io_queue_proc | io_uring/poll.c | function parameter, local variable, function parameter
| | | | io_poll_queue_proc | io_uring/poll.c | local variable
| | | | io_pollfree_wake | io_uring/poll.c | function parameter
| | | | io_poll_wake | io_uring/poll.c | local variable
| | | | io_poll_double_prepare | io_uring/poll.c | local variable
| | | | \_\_io_arm_poll_handler | io_uring/poll.c | function parameter
| | | | io_arm_poll_handler | io_uring/poll.c | field access
| | | | io_poll_add | io_uring/poll.c | local variable
| | | | io_poll_remove | io_uring/poll.c | local variable
async_poll | io_uring/poll.c | struct io_poll poll, struct io_poll \*double_poll | io_poll_get_double | io_uring/poll.c | field access
| | | | io_req_alloc_apoll | io_uring/poll.c | local variable, return value
| | | | io_arm_poll_handler | io_uring/poll.c | local variable
| | | | io_async_queue_proc | io_uring/poll.c | local variable, field access

### poll.h
Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_poll        | io_uring/poll.h | file, head, events, retries, wait | io_poll_add_prep | io_uring/poll.c | req->poll (member assignment)
| | | io_poll_add | io_uring/poll.c | req->poll (member usage)
| | | io_arm_poll_handler | io_uring/poll.c | req->poll (member usage)
| | | io_poll_task_func | io_uring/poll.c | req->poll (member usage)

async_poll     | io_uring/poll.h | poll, double_poll | io_poll_add | io_uring/poll.c | local variable
| | | io_poll_add_prep | io_uring/poll.c | local variable

### refs.h
Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_kiocb       | io_uring/refs.h | refs (atomic_t), flags | req_ref_inc_not_zero | io_uring/refs.h | function parameter
| | | req_ref_put_and_test_atomic | io_uring/refs.h | function parameter
| | | req_ref_put_and_test | io_uring/refs.h | function parameter
| | | req_ref_get | io_uring/refs.h | function parameter
| | | req_ref_put | io_uring/refs.h | function parameter
| | | __io_req_set_refcount | io_uring/refs.h | function parameter
| | | io_req_set_refcount | io_uring/refs.h | function parameter

### register.c
Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_uring_probe | io_uring/register.c | u8 last_op, u8 __resv[3], u32 ops_len, struct io_uring_probe_op ops[0] | io_probe | io_uring/register.c | local variable, function parameter
io_restriction | io_uring/register.c | unsigned long register_op[BITS_TO_LONGS(IORING_REGISTER_LAST)], unsigned long sqe_op[BITS_TO_LONGS(IORING_OP_LAST)], u32 sqe_flags_allowed, u32 sqe_flags_required | io_parse_restrictions | io_uring/register.c | function parameter
| | | | io_register_restrictions | io_uring/register.c | local variable
io_ring_ctx_rings | io_uring/register.c | struct io_rings \*rings, struct io_uring_sqe \*sq_sqes, struct io_mapped_region sq_region, struct io_mapped_region ring_region | io_register_free_rings | io_uring/register.c | function parameter
| | | | io_register_resize_rings | io_uring/register.c | local variable, pointer
io_uring_region_desc | io_uring/register.c | u64 addr, u64 len, u32 off, u32 resv, u32 flags, u64 user_addr | io_parse_restrictions | io_uring/register.c | local variable
| | | | io_register_restrictions | io_uring/register.c | local variable
| | | | io_register_resize_rings | io_uring/register.c | local variable, pointer
| | | | io_register_mem_region | io_uring/register.c | local variable, pointer
io_uring_mem_region_reg | io_uring/register.c | u64 region_uptr, u32 nr_regions, u32 flags, u32 __resv[3] | io_register_mem_region | io_uring/register.c | local variable, pointer

### register.h
Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_ring_ctx    | io_uring/register.h | (not shown in header) | io_eventfd_unregister | io_uring/register.h | function parameter
| | | io_unregister_personality | io_uring/register.h | function parameter
file           | io_uring/register.h | (not shown in header) | io_uring_register_get_file | io_uring/register.h | return value

### rsrc.c
Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_rsrc_update | io_uring/rsrc.c | struct file \*file, u64 arg, u32 nr_args, u32 offset | io_files_update_prep | io_uring/rsrc.c | local variable, function parameter
| | | | io_files_update | io_uring/rsrc.c | local variable
io_mapped_ubuf | io_uring/rsrc.c | unsigned long ubuf, size_t len, unsigned long acct_pages, unsigned int folio_shift, u16 nr_bvecs, u8 is_kbuf, u8 dir, refcount_t refs, void (\*release)(void \*), void \*priv, struct bio_vec bvec[0] | io_release_ubuf | io_uring/rsrc.c | function parameter
| | | | io_alloc_imu | io_uring/rsrc.c | return value
| | | | io_buffer_unmap | io_uring/rsrc.c | function parameter
| | | | io_buffer_account_pin | io_uring/rsrc.c | function parameter
| | | | io_sqe_buffer_register | io_uring/rsrc.c | local variable, field access
| | | | io_buffer_register_bvec | io_uring/rsrc.c | local variable, field access
| | | | io_buffer_unregister_bvec | io_uring/rsrc.c | field access
| | | | validate_fixed_range | io_uring/rsrc.c | function parameter
| | | | io_import_fixed | io_uring/rsrc.c | function parameter
| | | | io_import_reg_buf | io_uring/rsrc.c | field access
| | | | io_vec_fill_bvec | io_uring/rsrc.c | function parameter
| | | | io_estimate_bvec_size | io_uring/rsrc.c | function parameter
| | | | io_vec_fill_kern_bvec | io_uring/rsrc.c | function parameter
| | | | iov_kern_bvec_size | io_uring/rsrc.c | function parameter
| | | | io_kern_bvec_size | io_uring/rsrc.c | function parameter
| | | | io_import_reg_vec | io_uring/rsrc.c | field access
io_rsrc_node | io_uring/rsrc.c | int type, u64 tag, u64 file_ptr, union { struct io_mapped_ubuf \*buf; } data, int refs | io_rsrc_node_alloc | io_uring/rsrc.c | return value
| | | | io_rsrc_data_free | io_uring/rsrc.c | field access
| | | | __io_sqe_files_update | io_uring/rsrc.c | local variable
| | | | __io_sqe_buffers_update | io_uring/rsrc.c | local variable
| | | | io_sqe_files_register | io_uring/rsrc.c | local variable
| | | | io_buffer_register_bvec | io_uring/rsrc.c | local variable, field access
| | | | io_buffer_unregister_bvec | io_uring/rsrc.c | local variable
| | | | io_find_buf_node | io_uring/rsrc.c | local variable, return value
| | | | io_clone_buffers | io_uring/rsrc.c | local variable
| | | | io_free_rsrc_node | io_uring/rsrc.c | function parameter
| | | | io_rsrc_node_lookup | io_uring/rsrc.c | return value
io_rsrc_data | io_uring/rsrc.c | unsigned int nr, struct io_rsrc_node \*\*nodes | io_rsrc_data_alloc | io_uring/rsrc.c | function parameter, local variable
| | | | io_rsrc_data_free | io_uring/rsrc.c | function parameter
| | | | __io_sqe_files_update | io_uring/rsrc.c | field access
| | | | __io_sqe_buffers_update | io_uring/rsrc.c | field access
| | | | io_sqe_files_register | io_uring/rsrc.c | field access
| | | | io_buffer_register_bvec | io_uring/rsrc.c | local variable, field access
| | | | io_buffer_unregister_bvec | io_uring/rsrc.c | local variable, field access
| | | | io_clone_buffers | io_uring/rsrc.c | local variable, field access
io_imu_folio_data | io_uring/rsrc.c | unsigned int nr_pages_head, unsigned int nr_pages_mid, unsigned int nr_folios, unsigned int folio_shift | io_check_coalesce_buffer | io_uring/rsrc.c | function parameter, local variable
| | | | io_coalesce_buffer | io_uring/rsrc.c | function parameter, local variable
io_uring_rsrc_update2 | io_uring/rsrc.c | u64 offset, u64 data, u32 nr, u32 resv, u64 tags, u64 resv2 | __io_sqe_files_update | io_uring/rsrc.c | function parameter
| | | | __io_sqe_buffers_update | io_uring/rsrc.c | function parameter
| | | | __io_register_rsrc_update | io_uring/rsrc.c | function parameter
| | | | io_register_files_update | io_uring/rsrc.c | local variable
| | | | io_register_rsrc_update | io_uring/rsrc.c | local variable
io_uring_rsrc_register | io_uring/rsrc.c | u64 data, u32 nr, u32 resv, u64 tags, u64 resv2, u32 flags | io_register_rsrc | io_uring/rsrc.c | local variable, function parameter
io_uring_clone_buffers | io_uring/rsrc.c | u32 src_fd, u32 flags, u32 src_off, u32 dst_off, u32 nr, u32 pad[1] | io_clone_buffers | io_uring/rsrc.c | function parameter, local variable
| | | | io_register_clone_buffers | io_uring/rsrc.c | local variable, function parameter
iou_vec | io_uring/rsrc.c | struct iovec \*iovec, struct bio_vec \*bvec, unsigned nr | io_vec_realloc | io_uring/rsrc.c | function parameter, local variable
| | | | io_vec_fill_bvec | io_uring/rsrc.c | function parameter
| | | | io_vec_fill_kern_bvec | io_uring/rsrc.c | function parameter
| | | | io_import_reg_vec | io_uring/rsrc.c | function parameter, local variable
| | | | io_prep_reg_iovec | io_uring/rsrc.c | function parameter, local variable

### rsrc.h
Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_rsrc_node   | io_uring/rsrc.h | unsigned char type, int refs, u64 tag, union { unsigned long file_ptr; io_mapped_ubuf *buf } | io_rsrc_node_alloc | io_uring/rsrc.h | return value
| | | io_put_rsrc_node | io_uring/rsrc.h | function parameter
| | | io_free_rsrc_node | io_uring/rsrc.h | function parameter
| | | io_reset_rsrc_node | io_uring/rsrc.h | local variable
| | | io_req_put_rsrc_nodes | io_uring/rsrc.h | function parameter
| | | io_req_assign_rsrc_node | io_uring/rsrc.h | function parameter, pointer assignment
| | | io_req_assign_buf_node | io_uring/rsrc.h | function parameter
io_mapped_ubuf | io_uring/rsrc.h | u64 ubuf, unsigned int len, nr_bvecs, folio_shift; refcount_t refs; unsigned long acct_pages; void (*release)(void *); void *priv; bool is_kbuf; u8 dir; bio_vec bvec[] | (used indirectly via union in io_rsrc_node) | io_uring/rsrc.h | union member
io_imu_folio_data | io_uring/rsrc.h | unsigned int nr_pages_head, nr_pages_mid, folio_shift, nr_folios | io_check_coalesce_buffer | io_uring/rsrc.h | function parameter
io_ring_ctx    | io_uring/rsrc.h | (not shown) | io_rsrc_cache_init | io_uring/rsrc.h | function parameter
| | | io_rsrc_cache_free | io_uring/rsrc.h | function parameter
| | | io_rsrc_node_alloc | io_uring/rsrc.h | function parameter
| | | io_free_rsrc_node | io_uring/rsrc.h | function parameter
| | | io_rsrc_data_free | io_uring/rsrc.h | function parameter
| | | io_register_clone_buffers | io_uring/rsrc.h | function parameter
| | | io_sqe_buffers_unregister | io_uring/rsrc.h | function parameter
| | | io_sqe_buffers_register | io_uring/rsrc.h | function parameter
| | | io_sqe_files_unregister | io_uring/rsrc.h | function parameter
| | | io_sqe_files_register | io_uring/rsrc.h | function parameter
| | | io_register_files_update | io_uring/rsrc.h | function parameter
| | | io_register_rsrc_update | io_uring/rsrc.h | function parameter
| | | io_register_rsrc | io_uring/rsrc.h | function parameter
| | | io_put_rsrc_node | io_uring/rsrc.h | function parameter
io_rsrc_data   | io_uring/rsrc.h | (not shown) | io_rsrc_data_free | io_uring/rsrc.h | function parameter
| | | io_rsrc_data_alloc | io_uring/rsrc.h | function parameter
| | | io_rsrc_node_lookup | io_uring/rsrc.h | function parameter
| | | io_reset_rsrc_node | io_uring/rsrc.h | function parameter, local variable
io_kiocb       | io_uring/rsrc.h | (not shown) | io_find_buf_node | io_uring/rsrc.h | function parameter
| | | io_import_reg_buf | io_uring/rsrc.h | function parameter
| | | io_import_reg_vec | io_uring/rsrc.h | function parameter
| | | io_prep_reg_iovec | io_uring/rsrc.h | function parameter
| | | io_files_update | io_uring/rsrc.h | function parameter
| | | io_files_update_prep | io_uring/rsrc.h | function parameter
| | | io_req_put_rsrc_nodes | io_uring/rsrc.h | function parameter
| | | io_req_assign_buf_node | io_uring/rsrc.h | function parameter
iou_vec        | io_uring/rsrc.h | (not shown) | io_import_reg_vec | io_uring/rsrc.h | function parameter
| | | io_prep_reg_iovec | io_uring/rsrc.h | function parameter
| | | io_vec_free | io_uring/rsrc.h | function parameter
| | | io_vec_realloc | io_uring/rsrc.h | function parameter
| | | io_vec_reset_iovec | io_uring/rsrc.h | function parameter
| | | io_alloc_cache_vec_kasan | io_uring/rsrc.h | function parameter
user_struct    | io_uring/rsrc.h | (not shown) | __io_account_mem | io_uring/rsrc.h | function parameter
| | | __io_unaccount_mem | io_uring/rsrc.h | function parameter
iovec          | io_uring/rsrc.h | (standard struct) | io_buffer_validate | io_uring/rsrc.h | function parameter
| | | io_vec_reset_iovec | io_uring/rsrc.h | function parameter

### rw.c
Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_rw | io_uring/rw.c | struct kiocb kiocb, u64 addr, u32 len, rwf_t flags | io_iov_compat_buffer_select_prep | io_uring/rw.c | function parameter
| | | | io_iov_buffer_select_prep | io_uring/rw.c | local variable
| | | | io_import_vec | io_uring/rw.c | local variable
| | | | __io_import_rw_buffer | io_uring/rw.c | local variable
| | | | io_import_rw_buffer | io_uring/rw.c | function parameter
| | | | io_rw_recycle | io_uring/rw.c | local variable
| | | | io_req_rw_cleanup | io_uring/rw.c | local variable
| | | | io_rw_alloc_async | io_uring/rw.c | local variable
| | | | io_prep_rw_pi | io_uring/rw.c | local variable
| | | | __io_prep_rw | io_uring/rw.c | local variable
| | | | io_rw_do_import | io_uring/rw.c | local variable
| | | | io_prep_rw | io_uring/rw.c | local variable
| | | | io_prep_read | io_uring/rw.c | local variable
| | | | io_prep_write | io_uring/rw.c | local variable
| | | | io_prep_rwv | io_uring/rw.c | local variable
| | | | io_prep_readv | io_uring/rw.c | local variable
| | | | io_prep_writev | io_uring/rw.c | local variable
| | | | io_init_rw_fixed | io_uring/rw.c | local variable
| | | | io_prep_read_fixed | io_uring/rw.c | local variable
| | | | io_prep_write_fixed | io_uring/rw.c | local variable
| | | | io_rw_import_reg_vec | io_uring/rw.c | local variable
| | | | io_rw_prep_reg_vec | io_uring/rw.c | local variable
| | | | io_prep_readv_fixed | io_uring/rw.c | local variable
| | | | io_prep_writev_fixed | io_uring/rw.c | local variable
| | | | io_read_mshot_prep | io_uring/rw.c | local variable
| | | | io_readv_writev_cleanup | io_uring/rw.c | local variable
| | | | io_kiocb_update_pos | io_uring/rw.c | local variable, return value
| | | | io_rw_should_reissue | io_uring/rw.c | local variable
| | | | io_req_end_write | io_uring/rw.c | local variable
| | | | io_req_io_end | io_uring/rw.c | local variable
| | | | __io_complete_rw_common | io_uring/rw.c | local variable
| | | | io_fixup_rw_res | io_uring/rw.c | local variable
| | | | io_req_rw_complete | io_uring/rw.c | local variable
| | | | io_complete_rw | io_uring/rw.c | local variable, function parameter
| | | | io_complete_rw_iopoll | io_uring/rw.c | local variable, function parameter
| | | | io_rw_done | io_uring/rw.c | local variable
| | | | kiocb_done | io_uring/rw.c | local variable
| | | | loop_rw_iter | io_uring/rw.c | function parameter
| | | | io_async_buf_func | io_uring/rw.c | local variable
| | | | io_rw_should_retry | io_uring/rw.c | local variable
| | | | io_iter_do_read | io_uring/rw.c | local variable
| | | | need_complete_io | io_uring/rw.c | local variable
| | | | io_rw_init_file | io_uring/rw.c | local variable
| | | | __io_read | io_uring/rw.c | local variable
| | | | io_read | io_uring/rw.c | local variable
| | | | io_read_mshot | io_uring/rw.c | local variable
| | | | io_kiocb_start_write | io_uring/rw.c | local variable
| | | | io_write | io_uring/rw.c | local variable
| | | | io_read_fixed | io_uring/rw.c | local variable
| | | | io_write_fixed | io_uring/rw.c | local variable
| | | | io_rw_fail | io_uring/rw.c | local variable
| | | | io_uring_classic_poll | io_uring/rw.c | local variable
| | | | io_hybrid_iopoll_delay | io_uring/rw.c | local variable
| | | | io_uring_hybrid_poll | io_uring/rw.c | local variable
| | | | io_do_iopoll | io_uring/rw.c | local variable
| | | | io_rw_cache_free | io_uring/rw.c | function parameter
io_async_rw | io_uring/rw.c | struct iov_iter iter, struct iov_iter_state iter_state, struct iou_vec vec, struct iovec fast_iov, struct io_async_meta meta, struct io_async_meta_state meta_state, struct wait_page_queue wpq, long bytes_done | io_import_vec | io_uring/rw.c | function parameter
| | | | __io_import_rw_buffer | io_uring/rw.c | function parameter
| | | | io_import_rw_buffer | io_uring/rw.c | function parameter
| | | | io_rw_recycle | io_uring/rw.c | local variable, pointer
| | | | io_req_rw_cleanup | io_uring/rw.c | local variable
| | | | io_rw_alloc_async | io_uring/rw.c | local variable, return value
| | | | io_meta_save_state | io_uring/rw.c | function parameter
| | | | io_meta_restore | io_uring/rw.c | function parameter
| | | | io_prep_rw_pi | io_uring/rw.c | local variable, field access
| | | | __io_prep_rw | io_uring/rw.c | local variable
| | | | io_rw_do_import | io_uring/rw.c | local variable
| | | | io_prep_rw | io_uring/rw.c | local variable
| | | | io_prep_read | io_uring/rw.c | local variable
| | | | io_prep_write | io_uring/rw.c | local variable
| | | | io_prep_rwv | io_uring/rw.c | local variable
| | | | io_prep_readv | io_uring/rw.c | local variable
| | | | io_prep_writev | io_uring/rw.c | local variable
| | | | io_init_rw_fixed | io_uring/rw.c | local variable
| | | | io_prep_read_fixed | io_uring/rw.c | local variable
| | | | io_prep_write_fixed | io_uring/rw.c | local variable
| | | | io_rw_import_reg_vec | io_uring/rw.c | function parameter, local variable
| | | | io_rw_prep_reg_vec | io_uring/rw.c | local variable
| | | | io_prep_readv_fixed | io_uring/rw.c | local variable
| | | | io_prep_writev_fixed | io_uring/rw.c | local variable
| | | | io_read_mshot_prep | io_uring/rw.c | local variable
| | | | io_readv_writev_cleanup | io_uring/rw.c | local variable
| | | | io_rw_should_reissue | io_uring/rw.c | local variable
| | | | io_async_buf_func | io_uring/rw.c | local variable
| | | | io_rw_should_retry | io_uring/rw.c | local variable
| | | | __io_read | io_uring/rw.c | local variable
| | | | io_read | io_uring/rw.c | local variable
| | | | io_read_mshot | io_uring/rw.c | local variable
| | | | io_write | io_uring/rw.c | local variable
| | | | io_read_fixed | io_uring/rw.c | local variable
| | | | io_write_fixed | io_uring/rw.c | local variable
| | | | io_rw_fail | io_uring/rw.c | local variable
| | | | io_uring_classic_poll | io_uring/rw.c | local variable
| | | | io_uring_hybrid_poll | io_uring/rw.c | local variable
io_async_meta | io_uring/rw.c | struct iov_iter iter, u32 flags, u32 app_tag, u64 seed | io_meta_save_state | io_uring/rw.c | field access
| | | | io_meta_restore | io_uring/rw.c | function parameter
| | | | io_prep_rw_pi | io_uring/rw.c | field access
| | | | io_rw_should_retry | io_uring/rw.c | field access
io_async_meta_state | io_uring/rw.c | struct iov_iter_state iter_meta, u64 seed | io_meta_save_state | io_uring/rw.c | field access
| | | | io_meta_restore | io_uring/rw.c | field access
wait_page_queue | io_uring/rw.c | struct wait_queue_entry wait, struct page \*page | io_async_buf_func | local variable, function parameter
| | | | io_rw_should_retry | field access
io_uring_attr_pi | io_uring/rw.c | u64 addr, u32 len, u32 flags, u32 app_tag, u32 rsvd, u64 seed | io_prep_rw_pi | local variable, function parameter

### rw.h - zcrx.h

Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_meta_state  | io_uring/rw.h | u32 seed, iov_iter_state iter_meta                                                                                              | Used in direct I/O routines (via io_async_rw)              | io_uring/rw.h  | Holds metadata for direct I/O operations                        
io_async_rw    | io_uring/rw.h | iou_vec vec, size_t bytes_done, iov_iter iter, iov_iter_state iter_state, iovec fast_iov, union { wait_page_queue wpq; or { uio_meta meta, io_meta_state meta_state } } | Invoked in io_prep_read/write and related async routines  | io_uring/rw.h  | Provides context for asynchronous I/O (supports buffered & direct modes)
io_wq_work_list| io_uring/slist.h   | io_wq_work_node *first, io_wq_work_node *last            | wq_list_add_tail, wq_list_add_head, wq_list_cut   | io_uring/slist.h   | Manages the linked list of work nodes                 
io_wq_work_node| io_uring/slist.h   | io_wq_work_node *next                                   | wq_list_add_after, wq_stack_add_head, wq_stack_extract  | io_uring/slist.h   | Represents a node element in the work queue list      
io_wq_work     | io_uring/slist.h   | io_wq_work_node list                                   | wq_next_work                                    | io_uring/slist.h   | Encapsulates a work queue item (links work nodes)    
io_splice      | io_uring/splice.c    | file *file_out, loff_t off_out, loff_t off_in, u64 len, int splice_fd_in, unsigned int flags, io_rsrc_node *rsrc_node | __io_splice_prep, io_tee_prep, io_splice_cleanup, io_splice_get_file, io_tee, io_splice_prep, io_splice | io_uring/splice.c  | Used as a function parameter
io_tee_prep        | io_uring/splice.h    | (struct io_kiocb *req, const struct io_uring_sqe *sqe) -> int       | Tee operations                 | io_uring/splice.h   | Prepares tee
io_tee             | io_uring/splice.h    | (struct io_kiocb *req, unsigned int issue_flags) -> int            | Tee operations                 | io_uring/splice.h   | Executes tee
io_splice_cleanup  | io_uring/splice.h    | (struct io_kiocb *req) -> void                                    | Splice cleanup                 | io_uring/splice.h   | Cleanup
io_splice_prep     | io_uring/splice.h    | (struct io_kiocb *req, const struct io_uring_sqe *sqe) -> int       | Splice operations              | io_uring/splice.h   | Prepares splice
io_splice          | io_uring/splice.h    | (struct io_kiocb *req, unsigned int issue_flags) -> int            | Splice operations              | io_uring/splice.h   | Executes splice
io_sq_thread_unpark     | io_uring/sqpoll.c    | (struct io_sq_data *sqd) -> void                              | SQ event handling                                   | io_uring/sqpoll.c      | Unparks SQ thread
io_sq_thread_park       | io_uring/sqpoll.c    | (struct io_sq_data *sqd) -> void                              | SQ thread management                                | io_uring/sqpoll.c      | Parks SQ thread
io_sq_thread_stop       | io_uring/sqpoll.c    | (struct io_sq_data *sqd) -> void                              | Signals thread stop                                 | io_uring/sqpoll.c      | Stops SQ thread
io_put_sq_data          | io_uring/sqpoll.c    | (struct io_sq_data *sqd) -> void                              | Releases and cleans up SQ data                      | io_uring/sqpoll.c      | Reclaims SQ data
io_sqd_update_thread_idle| io_uring/sqpoll.c   | (struct io_sq_data *sqd) -> void                              | Updates idle time from context list               | io_uring/sqpoll.c      | Updates idle time
io_sq_thread_finish     | io_uring/sqpoll.c    | (struct io_ring_ctx *ctx) -> void                             | Cleans up SQ thread for a given context             | io_uring/sqpoll.c      | Finishes SQ thread
io_attach_sq_data       | io_uring/sqpoll.c    | (struct io_uring_params *p) -> struct io_sq_data*              | Attaches SQ data from existing FD                   | io_uring/sqpoll.c      | Attaches SQ data
io_get_sq_data          | io_uring/sqpoll.c    | (struct io_uring_params *p, bool *attached) -> struct io_sq_data*| Retrieves or allocates SQ data                      | io_uring/sqpoll.c      | Gets/allocates SQ data
io_sqd_events_pending   | io_uring/sqpoll.c    | (struct io_sq_data *sqd) -> bool                              | Checks SQ event flags                                | io_uring/sqpoll.c      | Checks events
io_sq_thread          | io_uring/sqpoll.c    | (struct io_ring_ctx *ctx, bool cap_entries) -> int             | Submits SQ entries with cap if needed              | io_uring/sqpoll.c      | Submits SQEs
io_sqd_handle_event     | io_uring/sqpoll.c    | (struct io_sq_data *sqd) -> bool                              | Processes pending SQ events                         | io_uring/sqpoll.c      | Processes events
io_sq_tw                | io_uring/sqpoll.c    | (struct llist_node **retry_list, int max_entries) -> unsigned int| Processes task work from retry list                | io_uring/sqpoll.c      | Runs task work
io_sq_tw_pending        | io_uring/sqpoll.c    | (struct llist_node *retry_list) -> bool                        | Checks for pending task work                        | io_uring/sqpoll.c      | Checks task work
io_sq_update_worktime   | io_uring/sqpoll.c    | (struct io_sq_data *sqd, struct rusage *start) -> void          | Updates work time based on rusage                   | io_uring/sqpoll.c      | Updates work time
io_sq_thread            | io_uring/sqpoll.c    | (void *data) -> int                                             | Main SQ polling loop (executes submissions/task work)| io_uring/sqpoll.c      | SQ thread loop
io_sqpoll_wait_sq         | io_uring/sqpoll.c    | (struct io_ring_ctx *ctx) -> void                                       | Internal SQ poll routines                 | io_uring/sqpoll.c      | Waits for SQ avail.
io_sq_offload_create      | io_uring/sqpoll.c    | (struct io_ring_ctx *ctx, struct io_uring_params *p) -> int               | SQ poll setup/offload                      | io_uring/sqpoll.c      | Creates SQ poll thread.
io_sqpoll_wq_cpu_affinity | io_uring/sqpoll.c    | (struct io_ring_ctx *ctx, cpumask_var_t mask) -> int                      | SQ poll CPU affinity config                | io_uring/sqpoll.c      | Sets CPU affinity.
io_sq_data     | io_uring/sqpoll.h  | refcount_t refs, atomic_t park_pending, struct mutex lock, struct list_head ctx_list, struct task_struct *thread, struct wait_queue_head wait, unsigned sq_thread_idle, int sq_cpu, pid_t task_pid, pid_t task_tgid, u64 work_time, unsigned long state, struct completion exited | Used by SQ polling functions  | io_uring/sqpoll.h   | SQ polling data
io_sq_offload_create         | io_uring/sqpoll.h  | (struct io_ring_ctx *ctx, struct io_uring_params *p) -> int              | SQ poll setup                | io_uring/sqpoll.h   | Create offload
io_sq_thread_finish          | io_uring/sqpoll.h  | (struct io_ring_ctx *ctx) -> void                                      | SQ cleanup                   | io_uring/sqpoll.h   | Finish thread
io_sq_thread_stop            | io_uring/sqpoll.h  | (struct io_sq_data *sqd) -> void                                       | SQ stop                      | io_uring/sqpoll.h   | Stop thread
io_sq_thread_park            | io_uring/sqpoll.h  | (struct io_sq_data *sqd) -> void                                       | SQ thread control            | io_uring/sqpoll.h   | Park thread
io_sq_thread_unpark          | io_uring/sqpoll.h  | (struct io_sq_data *sqd) -> void                                       | SQ thread control            | io_uring/sqpoll.h   | Unpark thread
io_put_sq_data               | io_uring/sqpoll.h  | (struct io_sq_data *sqd) -> void                                       | SQ data cleanup              | io_uring/sqpoll.h   | Release data
io_sqpoll_wait_sq            | io_uring/sqpoll.h  | (struct io_ring_ctx *ctx) -> void                                      | SQ polling wait              | io_uring/sqpoll.h   | Wait for SQ
io_sqpoll_wq_cpu_affinity    | io_uring/sqpoll.h  | (struct io_ring_ctx *ctx, cpumask_var_t mask) -> int                     | SQ CPU affinity              | io_uring/sqpoll.h   | Set CPU affinity
io_statx       | io_uring/statx.c   | file *file, int dfd, unsigned int mask, unsigned int flags, filename *filename, statx __user *buffer | io_statx_prep, io_statx, io_statx_cleanup             | io_uring/statx.c     | Request details
io_statx_prep      | io_uring/statx.c   | (struct io_kiocb *req, const struct io_uring_sqe *sqe) -> int                  | Prepares statx request       | io_uring/statx.c     | Prep statx
io_statx           | io_uring/statx.c   | (struct io_kiocb *req, unsigned int issue_flags) -> int                       | Executes statx syscall       | io_uring/statx.c     | Execute statx
io_statx_cleanup   | io_uring/statx.c   | (struct io_kiocb *req) -> void                                                 | Cleans up statx request      | io_uring/statx.c     | Cleanup statx
io_statx_prep      | io_uring/statx.h    | (struct io_kiocb *req, const struct io_uring_sqe *sqe) -> int               | statx operations          | io_uring/statx.h    | Prep statx
io_statx           | io_uring/statx.h    | (struct io_kiocb *req, unsigned int issue_flags) -> int                    | statx operations          | io_uring/statx.h    | Execute statx
io_statx_cleanup   | io_uring/statx.h    | (struct io_kiocb *req) -> void                                             | statx cleanup             | io_uring/statx.h    | Cleanup statx
io_sync        | io_uring/sync.c    | file *file, loff_t len, loff_t off, int flags, int mode               | io_sfr_prep, io_sync_file_range, io_fsync_prep, io_fsync, io_fallocate_prep, io_fallocate | io_uring/sync.c      | Sync req details
io_sfr_prep           | io_uring/sync.c    | (struct io_kiocb *req, const struct io_uring_sqe *sqe) -> int              | Sync file_range          | io_uring/sync.c     | Prep sync_range
io_sync_file_range    | io_uring/sync.c    | (struct io_kiocb *req, unsigned int issue_flags) -> int                   | Sync file_range          | io_uring/sync.c     | Exec sync_range
io_fsync_prep         | io_uring/sync.c    | (struct io_kiocb *req, const struct io_uring_sqe *sqe) -> int              | Fsync                    | io_uring/sync.c     | Prep fsync
io_fsync              | io_uring/sync.c    | (struct io_kiocb *req, unsigned int issue_flags) -> int                   | Fsync                    | io_uring/sync.c     | Exec fsync
io_fallocate_prep     | io_uring/sync.c    | (struct io_kiocb *req, const struct io_uring_sqe *sqe) -> int              | Fallocate                | io_uring/sync.c     | Prep fallocate
io_fallocate          | io_uring/sync.c    | (struct io_kiocb *req, unsigned int issue_flags) -> int                   | Fallocate                | io_uring/sync.c     | Exec fallocate
io_sfr_prep           | io_uring/sync.h    | (struct io_kiocb *req, const struct io_uring_sqe *sqe) -> int             | Sync range prep              | io_uring/sync.h     | Prep sync range
io_sync_file_range    | io_uring/sync.h    | (struct io_kiocb *req, unsigned int issue_flags) -> int                  | Sync file_range exec         | io_uring/sync.h     | Exec sync range
io_fsync_prep         | io_uring/sync.h    | (struct io_kiocb *req, const struct io_uring_sqe *sqe) -> int             | Fsync prep                   | io_uring/sync.h     | Prep fsync
io_fsync              | io_uring/sync.h    | (struct io_kiocb *req, unsigned int issue_flags) -> int                  | Fsync exec                   | io_uring/sync.h     | Exec fsync
io_fallocate          | io_uring/sync.h    | (struct io_kiocb *req, unsigned int issue_flags) -> int                  | Fallocate exec               | io_uring/sync.h     | Exec fallocate
io_fallocate_prep     | io_uring/sync.h    | (struct io_kiocb *req, const struct io_uring_sqe *sqe) -> int             | Fallocate prep               | io_uring/sync.h     | Prep fallocate
io_tctx_node   | io_uring/tctx.h  | list_head ctx_node, task_struct *task, io_ring_ctx *ctx                        | Used in tctx management  | io_uring/tctx.h  | Maps task & ctx
io_timeout     | io_uring/timeout.c    | file *file, u32 off, u32 target_seq, u32 repeats, list_head list, io_kiocb *head, io_kiocb *prev      | Used by timeout handling functions (e.g., io_timeout_fn, io_timeout_complete, io_flush_timeouts)   | io_uring/timeout.c     | Timeout request metadata 
io_timeout_rem | io_uring/timeout.c    | file *file, u64 addr, timespec64 ts, u32 flags, bool ltimeout                                         | Utilized in timeout update routines                                                             | io_uring/timeout.c     | Holds update details 
io_timeout_data  | io_uring/timeout.h      | io_kiocb *req, hrtimer timer, timespec64 ts, hrtimer_mode mode, u32 flags      | Used by timeout management functions   | io_uring/timeout.h     | Holds timeout state information
io_ftrunc      | io_uring/truncate.c   | file *file, loff_t len               | io_ftruncate_prep, io_ftruncate | io_uring/truncate.c   | Holds file truncation parameters
io_async_cmd   | io_uring/uring_cmd.h      | io_uring_cmd_data data, iou_vec vec, io_uring_sqe sqes[2]          | Utilized in asynchronous command handling | io_uring/uring_cmd.h    | Holds async command details
io_waitid      | io_uring/waitid.c      | file *file, int which, pid_t upid, int options, atomic_t refs, wait_queue_head *head, siginfo __user *infop, waitid_info info | Used by functions handling async waitid notifications (e.g., io_waitid_prep, io_waitid, io_waitid_complete) | io_uring/waitid.c     | Holds waitid notification state
io_waitid_async  | io_uring/waitid.h    | struct io_kiocb *req, struct wait_opts wo       | Used in async waitid processes       | io_uring/waitid.h     | Holds asynchronous waitid data
io_xattr       | io_uring/xattr.c     | file *file, kernel_xattr_ctx ctx, filename *filename                     | Used by xattr operations (get/set xattr functions) | io_uring/xattr.c      | Holds extended attribute context and related data
io_zcrx_args   | io_uring/zcrx.c      | struct io_kiocb *req; struct io_zcrx_ifq *ifq; struct socket *sock; unsigned nr_skbs;  | Used by zcrx functions to pass zero‑copy RX arguments  | io_uring/zcrx.c      | Holds parameters for zcrx operations
io_zcrx_args   | io_uring/zcrx.c      | struct io_kiocb *req; struct io_zcrx_ifq *ifq; struct socket *sock; unsigned nr_skbs;  | Used by zcrx functions to pass zero‑copy RX arguments      | io_uring/zcrx.c      | Holds parameters for zcrx operations
io_zcrx_area   | io_uring/zcrx.h      | struct net_iov_area nia; struct io_zcrx_ifq *ifq; atomic_t *user_refs; bool is_mapped; u16 area_id; struct page **pages; spinlock_t freelist_lock; u32 free_count; u32 *freelist; | Used to manage the zero‑copy receive buffer area and free index list | io_uring/zcrx.h      | Represents the shared memory area for zero‑copy buffers
io_zcrx_ifq    | io_uring/zcrx.h      | struct io_ring_ctx *ctx; struct io_zcrx_area *area; struct io_uring *rq_ring; struct io_uring_zcrx_rqe *rqes; u32 rq_entries; u32 cached_rq_head; spinlock_t rq_lock; u32 if_rxq; struct device *dev; struct net_device *netdev; netdevice_tracker netdev_tracker; spinlock_t lock; | Accessed by zcrx functions for managing zero‑copy RX operations | io_uring/zcrx.h      | Represents the zero‑copy RX interface queue linking io_uring context and network device buffers
