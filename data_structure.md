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
io_ev_fd       | io_uring/eventfd.c | eventfd_ctx, uint, uint, refcount_t, atomic_t, rcu_head | io_eventfd_free | io_uring/eventfd.c | local variable
| | | | io_eventfd_put | io_uring/eventfd.c | function parameter
| | | | io_eventfd_do_signal | io_uring/eventfd.c | local variable, function parameter
| | | | __io_eventfd_signal | io_uring/eventfd.c | function parameter
| | | | io_eventfd_grab | io_uring/eventfd.c | return value, local variable
| | | | io_eventfd_signal | io_uring/eventfd.c | local variable 
| | | | io_eventfd_flush_signal | io_uring/eventfd.c | local variable
| | | | io_eventfd_register | io_uring/eventfd.c | local variable
| | | | io_eventfd_unregister | io_uring/eventfd.c | function parameter
io_kiocb_to_cmd        | io_uring/advise.c                  | req, struct io_madvise                                             | io_kiocb_to_cmd           | advise.c                         | function parameter
o_req_set_res        | advise.c                  | req, ret, 0                                                       | io_req_set_res            | advise.c                         | function parameter  
READ_ONCE            | advise.c                  | sqe->addr                                                         | READ_ONCE                | advise.c                         | function parameter                
req_set_fail          | advise.c                  | req                                                               | req_set_fail              | advise.c     
WARN_ON_ONCE          | advise.c                  | issue_flags & IO_URING_F_NONBLOCK                                 | WARN_ON_ONCE              | advise.c                         | function parameter 
if                     | advise.c                   | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                                | if                      | advise.c                        | macro                            
io_kiocb_to_cmd        | advise.c                   | req, struct io_madvise                                             | io_kiocb_to_cmd         | advise.c                        | function definition
if                     | advise.c                   | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                                | if                      | advise.c                        | macro
READ_ONCE             | advise.c                   | sqe->addr                                                          | READ_ONCE               | advise.c                        | function definition
switch                 | advise.c                   | fa->advice                                                       | switch                  | advise.c                        | conditional branch
if                     | advise.c                   | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                                | if                      | advise.c                        | macro
io_kiocb_to_cmd        | advise.c                   | req, struct io_madvise                                            | io_kiocb_to_cmd         | advise.c                        | function call
io_req_set_res         | advise.c                   | req, ret, 0                                                       | io_req_set_res          | advise.c                        | function call
READ_ONCE              | advise.c                   | sqe->addr                                                         | READ_ONCE               | advise.c                        | function call
req_set_fail           | advise.c                   | req                                                               | req_set_fail            | advise.c                        | function call
io_req_set_res            | advise.c     | req, ret, 0                                         | io_req_set_res            | advise.c          | function call
READ_ONCE                | advise.c     | sqe->addr                                            | READ_ONCE                | advise.c          | function call
req_set_fail             | advise.c     | req                                                  | req_set_fail             | advise.c          | function call
user_access_end           | advise.c     | issue_flags & IO_URING_F_NONBLOCK                      | user_access_end           | advise.c          | function call
if                        | advise.c     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                    | if                        | advise.c          | conditional
io_kiocb_to_cmd           | advise.c     | req, struct io_madvise                                 | io_kiocb_to_cmd           | advise.c          | function call
io_req_set_res            | advise.c     | req, ret, 0                                            | io_req_set_res            | advise.c          | function call
READ_ONCE                  | advise.c     | sqe->addr                                               | READ_ONCE                  | advise.c          | macro
req_set_fail               | advise.c     | req                                                     | req_set_fail               | advise.c          | function call
WARN_ON_ONCE               | advise.c     | issue_flags & IO_URING_F_NONBLOCK                        | WARN_ON_ONCE               | advise.c          | macro
if                         | advise.c     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                      | if                         | advise.c          | conditional
READ_ONCE                  | advise.c     | sqe->addr                                               | READ_ONCE                  | advise.c          | macro
if                         | advise.c     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                      | if                         | advise.c          | conditional
if                           | advise.c     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                      | if                           | advise.c          | conditional
io_kiocb_to_cmd              | advise.c     | req, struct io_madvise                                   | io_kiocb_to_cmd              | advise.c          | function call
io_req_set_res               | advise.c     | req, ret, 0                                              | io_req_set_res               | advise.c          | function call
READ_ONCE                    | advise.c     | sqe->addr                                                | READ_ONCE                    | advise.c          | macro
WARN_ON_ONCE                 | advise.c     | issue_flags & IO_URING_F_NONBLOCK                        | WARN_ON_ONCE                 | advise.c          | macro
if                             | advise.c     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                    | if                             | advise.c          | conditional
io_kiocb_to_cmd                | advise.c     | req, struct io_madvise                                | io_kiocb_to_cmd                | advise.c          | function call
io_req_set_res                 | advise.c     | req, ret, 0                                           | io_req_set_res                 | advise.c          | function call
READ_ONCE                      | advise.c     | sqe->addr                                             | READ_ONCE                      | advise.c          | macro
WARN_ON_ONCE                   | advise.c     | issue_flags & IO_URING_F_NONBLOCK                     | WARN_ON_ONCE                   | advise.c          | macro
CLASS        
if                             | advise.c     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                    | if                             | advise.c          | conditional
io_kiocb_to_cmd                | advise.c     | req, struct io_madvise                                | io_kiocb_to_cmd                | advise.c          | function call
io_req_set_res                 | advise.c     | req, ret, 0                                           | io_req_set_res                 | advise.c          | function call
READ_ONCE                      | advise.c     | sqe->addr                                             | READ_ONCE                      | advise.c          | macro
req_set_fail                   | advise.c     | req                                                   | req_set_fail                   | advise.c          | function call
switch                         | advise.c     | fa->advice                                             | switch                         | advise.c  
WARN_ON_ONCE                   | advise.c     | issue_flags & IO_URING_F_NONBLOCK                       | WARN_ON_ONCE                   | advise.c          | macro
defined                         | advise.c     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                    | defined                         | advise.c          | macro
if                              | advise.c     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                    | if                              | advise.c          | conditional
WARN_ON_ONCE                    | advise.c     | issue_flags & IO_URING_F_NONBLOCK                      | WARN_ON_ONCE                    | advise.c          | macro
if                             | advise.c     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                    | if                             | advise.c         | conditional
io_kiocb_to_cmd               | advise.c     | req, struct io_madvise                                  | io_kiocb_to_cmd               | advise.c         | function call
io_req_set_res                 | advise.c     | req, ret, 0                                             | io_req_set_res                 | advise.c         | function call
READ_ONCE                      | advise.c     | sqe->addr                                              | READ_ONCE                      | advise.c         | macro
req_set_fail                   | advise.c     | req                                                    | req_set_fail                   | advise.c         | function call
WARN_ON_ONCE                   | advise.c     | issue_flags & IO_URING_F_NONBLOCK                      | WARN_ON_ONCE                   | advise.c         | macro
io_req_set_res                 | advise.c     | req, ret, 0                                             | io_req_set_res                 | advise.c         | function call
READ_ONCE                      | advise.c     | sqe->addr                                              | READ_ONCE                      | advise.c         | macro
req_set_fail                   | advise.c     | req                                                    | req_set_fail                   | advise.c         | function call
switch                          | advise.c     | fa->advice                                             | switch                          | advise.c         | keyword
WARN_ON_ONCE                   | advise.c     | issue_flags & IO_URING_F_NONBLOCK                      | WARN_ON_ONCE                   | advise.c         | macro
if                     | advise.c                  | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)                 | if                      | advise.c                       | macro 
io_kiocb_to_cmd        | advise.c                  | struct io_madvise *ma = io_kiocb_to_cmd(req, struct io_madvise)            | io_kiocb_to_cmd         | advise.c                       | function call 
io_req_set_res         | advise.c                  | io_req_set_res(req, ret, 0)                                               | io_req_set_res          | advise.c                       | function call
READ_ONCE             | advise.c                  | ma->addr = READ_ONCE(sqe->addr)                                           | READ_ONCE              | advise.c                       | function call
return                  | advise.c         | return -EINVAL;                                                                   | return                    | advise.c               | keyword / control statement
switch                  | advise.c         | switch (fa->advice) {                                                              | switch                    | advise.c               | keyword / control statement
WARN_ON_ONCE            | advise.c         | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);                                  | WARN_ON_ONCE              | advise.c               | macro / debugging macro
READ_ONCE              | advise.c                   | READ_ONCE(sqe->addr)                                             | READ_ONCE               | advise.c                       | function call
req_set_fail           | advise.c                   | req_set_fail(req)                                                | req_set_fail            | advise.c                       | function call                  
return                 | advise.c                   | return -EINVAL;                                                  | return                  | advise.c                       | keyword
switch                 | advise.c                   | switch (fa->advice)                                              | switch                  | advise.c                       | conditional branch
WARN_ON_ONCE           | advise.c                   | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK)                  | WARN_ON_ONCE            | advise.c                       | macro
io_kiocb_to_cmd         | advise.c                  | req, struct io_madvise                                           | io_kiocb_to_cmd         | advise.c                       | function call
io_req_set_res         | advise.c                     | req, ret, 0                                          | io_req_set_res          | advise.c                       | function call
if                     | advise.c                     | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                  | if                      | advise.c                       | macro  
io_kiocb_to_cmd        | advise.c                     | io_kiocb_to_cmd(req, struct io_madvise)            | io_kiocb_to_cmd         | advise.c                       | function call
READ_ONCE              | advise.c                     | READ_ONCE(sqe->addr)                                | READ_ONCE               | advise.c                       | macro 
WARN_ON_ONCE           | advise.c                     | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK)    | WARN_ON_ONCE            | advise.c                       | macro  
if                     | advise.c                   | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)      | if                     | advise.c                        | macro
READ_ONCE                      | advise.c                 | ma->addr = READ_ONCE(sqe->addr);                          | READ_ONCE                    | advise.c                   | macro 
WARN_ON_ONCE           | advise.c                   | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);                  | WARN_ON_ONCE            | advise.c                      | macro 
bool                    | advise.c                   | io_fadvise_force_async(struct io_fadvise *fa)                     | bool                    | advise.c                        | function definition
if                      | advise.c                   | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)       | if                      | advise.c                        | macro (preprocessor) 
READ_ONCE               | advise.c                   | ma->addr = READ_ONCE(sqe->addr)                                   | READ_ONCE               | advise.c                        | function call
switch                  | advise.c                   | switch (fa->advice)                                               | switch                  | advise.c                        | conditional branch
io_kiocb_to_cmd          | advise.c         | req, struct io_madvise                     | io_kiocb_to_cmd          | advise.c         | macro / cast
io_req_set_res              | advise.c      | req, ret, 0                              | io_req_set_res             | advise.c      | function call
READ_ONCE                   | advise.c      | sqe->addr                                | READ_ONCE                  | advise.c      | macro
req_set_fail                | advise.c      | req                                      | req_set_fail               | advise.c      | function call
return                      | advise.c      | return -EINVAL                           | return                     | advise.c      | keyword
WARN_ON_ONCE                | advise.c      | issue_flags                              | WARN_ON_ONCE               | advise.c      | macro
bool                    | advise.c                  | static bool io_fadvise_force_async(struct io_fadvise *fa)       | bool                   | advise.c                       | type definition
if                      | advise.c                  | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)       | if                      | advise.c                       | preprocessor directive
switch                | advise.c                   | switch (fa->advice)                                               | switch                | advise.c                   | conditional branch
WARN_ON_ONCE          | advise.c                   | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);                 | WARN_ON_ONCE          | advise.c                   | function call
defined                | advise.c                   | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                                | defined                 | advise.c                        | macro
if                     | advise.c                   | CONFIG_ADVISE_SYSCALLS, CONFIG_MMU                                | if                      | advise.c                        | macro
io_kiocb_to_cmd        | advise.c                   | req, struct io_madvise                                            | io_kiocb_to_cmd         | advise.c                        | function call
io_req_set_res         | advise.c                   | req, ret, 0                                                       | io_req_set_res          | advise.c                        | function call
READ_ONCE              | advise.c                   | sqe->addr                                                         | READ_ONCE               | advise.c                        | function call
req_set_fail           | advise.c                   | req                                                               | req_set_fail            | advise.c                        | function call
if                     | advise.c                   | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)      | if                      | advise.c                        | macro
io_req_set_res                   | advise.c        | io_req_set_res(req, ret, 0);                                      | io_req_set_res               | advise.c        | function call 
READ_ONCE             | advise.c                  | ma->addr = READ_ONCE(sqe->addr)                                | READ_ONCE             | advise.c  
req_set_fail           | advise.c                  | req_set_fail(req)                                              | req_set_fail           | advise.c                       | function call
switch                | advise.c                   | fa->advice                                                       | switch                 | advise.c                      | conditional branch
true                  | advise.c                   | return true                                                        | true                   | advise.c                      | return statement
WARN_ON_ONCE          | advise.c                   | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);                  | WARN_ON_ONCE           | advise.c                      | function call  
if                       | advise.c                   | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)       | if                       | advise.c                       | macro
io_kiocb_to_cmd          | advise.c                   | struct io_madvise *ma = io_kiocb_to_cmd(req, struct io_madvise); | io_kiocb_to_cmd          | advise.c                       | function call
io_req_set_res           | advise.c                   | io_req_set_res(req, ret, 0);                                    | io_req_set_res           | advise.c                       | function call
READ_ONCE                | advise.c                   | ma->addr = READ_ONCE(sqe->addr);                                | READ_ONCE                | advise.c                       | function call
WARN_ON_ONCE             | advise.c                   | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);               | WARN_ON_ONCE             | advise.c                       | function call
if                       | advise.c                   | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)       | if                       | advise.c                       | macro
return                  | advise.c                   | return -EINVAL;                                                           | return                  | advise.c                       | function call
switch                  | advise.c                   | switch (fa->advice) {                                                     | switch                  | advise.c                       | statement
WARN_ON_ONCE            | advise.c                   | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);                          | WARN_ON_ONCE            | advise.c                       | function call
do_madvise             | advise.c                   | ret = do_madvise(current->mm, ma->addr, ma->len, ma->advice);                     | do_madvise             | advise.c                     | function call
if                     | advise.c                   | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)                          | if                     | advise.c                     | conditional directive
io_fadvise             | advise.c                   | struct io_fadvise {                                                                | io_fadvise             | advise.c                     | structure definition
io_fadvise_force_async | advise.c                   | static bool io_fadvise_force_async(struct io_fadvise *fa)                          | io_fadvise_force_async | advise.c                     | function definition
io_fadvise_prep        | advise.c                   | int io_fadvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)           | io_fadvise_prep        | advise.c                     | function definition
io_kiocb_to_cmd        | advise.c                   | struct io_madvise *ma = io_kiocb_to_cmd(req, struct io_madvise);                   | io_kiocb_to_cmd        | advise.c                     | function call
io_madvise             | advise.c                   | struct io_madvise {                                                                | io_madvise             | advise.c                     | structure definition
io_madvise_prep        | advise.c                   | int io_madvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)           | io_madvise_prep        | advise.c                     | function definition
io_req_set_res         | advise.c                   | io_req_set_res(req, ret, 0);                                                      | io_req_set_res         | advise.c                     | function call
READ_ONCE              | advise.c                   | ma->addr = READ_ONCE(sqe->addr);                                                  | READ_ONCE              | advise.c                     | macro
req_set_fail           | advise.c                   | req_set_fail(req);                                                                | req_set_fail           | advise.c                     | function call
switch                 | advise.c                   | switch (fa->advice) {                                                             | switch                 | advise.c                     | statement
vfs_fadvise            | advise.c                   | ret = vfs_fadvise(req->file, fa->offset, fa->len, fa->advice);                     | vfs_fadvise            | advise.c                     | function call
WARN_ON_ONCE           | advise.c                   | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);                                  | WARN_ON_ONCE           | advise.c                     | function call
if                      | advise.c                   | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)                     | if                      | advise.c                     | preprocessor directive
io_kiocb_to_cmd         | advise.c                   | struct io_madvise *ma = io_kiocb_to_cmd(req, struct io_madvise);               | io_kiocb_to_cmd         | advise.c                     | function call
io_req_set_res          | advise.c                   | io_req_set_res(req, ret, 0);                                                  | io_req_set_res          | advise.c                     | function call
READ_ONCE               | advise.c                   | ma->addr = READ_ONCE(sqe->addr);                                               | READ_ONCE               | advise.c                     | macro
WARN_ON_ONCE            | advise.c                   | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);                               | WARN_ON_ONCE            | advise.c                     | function call
if                      | advise.c                   | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)                    | if                      | advise.c                     | preprocessor directive
READ_ONCE             | advise.c                   | sqe->addr                                                       | READ_ONCE              | advise.c                        | function call    
switch                | advise.c                   | fa->advice                                                      | switch                 | advise.c                        | conditional branch  
WARN_ON_ONCE          | advise.c                   | issue_flags & IO_URING_F_NONBLOCK                               | WARN_ON_ONCE           | advise.c                        | macro     
READ_ONCE               | advise.c         | READ_ONCE(sqe->addr)                                            | READ_ONCE               | advise.c                        | macro 
req_set_fail            | advise.c         | req_set_fail(req)                                               | req_set_fail            | advise.c                        | function call      
switch                  | advise.c         | switch (fa->advice)                                             | switch                  | advise.c                        | keyword   
WARN_ON_ONCE            | advise.c         | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK)               | WARN_ON_ONCE            | advise.c                        | macro    
defined                   | advise.c                  | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)                 | defined                   | advise.c                      | macro 
if                        | advise.c                  | #if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)                 | if                        | advise.c                      | macro   
io_kiocb_to_cmd           | advise.c                  | struct io_madvise *ma = io_kiocb_to_cmd(req, struct io_madvise);           | io_kiocb_to_cmd           | advise.c                      | function call
io_req_set_res            | advise.c                  | io_req_set_res(req, ret, 0);                                              | io_req_set_res            | advise.c                      | function call 
READ_ONCE                  | advise.c                  | ma->addr = READ_ONCE(sqe->addr);                                            | READ_ONCE                  | advise.c                      | function call                   
req_set_fail               | advise.c                  | req_set_fail(req);                                                          | req_set_fail               | advise.c                      | function call    
switch                     | advise.c                  | switch (fa->advice) {                                                       | switch                     | advise.c                      | conditional branch   
WARN_ON_ONCE               | advise.c                  | WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);                            | WARN_ON_ONCE               | advise.c                      | macro 
io_kiocb_to_cmd         | advise.c                  | struct io_madvise *ma = io_kiocb_to_cmd(req, struct io_madvise);            | io_kiocb_to_cmd         | advise.c                     | function call 
io_req_set_res          | advise.c                  | io_req_set_res(req, ret, 0);                                               | io_req_set_res          | advise.c                     | function call 
READ_ONCE              | advise.c                  | ma->addr = READ_ONCE(sqe->addr);                                            | READ_ONCE              | advise.c                     | macro call                      
req_set_fail           | advise.c                  | req_set_fail(req);                                                          | req_set_fail           | advise.c                     | function call  
io_madvise_prep | advise.h | struct io_kiocb*, struct io_uring_sqe* | io_madvise_prep | io_uring/advise.h | function to prepare madvise operation  |
io_madvise | advise.h | struct io_kiocb*, unsigned int | io_madvise | io_uring/advise.h | function to perform madvise operation    |
io_fadvise_prep | advise.h | struct io_kiocb*, struct io_uring_sqe* | io_fadvise_prep | io_uring/advise.h | function to prepare fadvise operation  |
io_fadvise | advise.h | struct io_kiocb*, unsigned int | io_fadvise | io_uring/advise.h | function to perform fadvise operation    |
memset                | alloc_cache.c             | obj, cache->init_clear                                            | memset                   | alloc_cache.c                    | function parameter 
sizeof                | alloc_cache.c             | cache->entries                                                    | sizeof                   | alloc_cache.c                    | function parameter 
while                 | alloc_cache.c             | entry                                                            | while                     | alloc_cache.c                    | function parameter  
sizeof                | alloc_cache.c              | cache->entries                                                     | sizeof                  | alloc_cache
sizeof                   | alloc_cache.c| void *                                               | sizeof                   | alloc_cache.c     | macro
while                     | alloc_cache.c| io_alloc_cache_get(cache) != NULL                      | while                     | alloc_cache.c     | loop
sizeof                     | alloc_cache.c| cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL) | sizeof                     | alloc_cache.c     | operator
kmalloc                    | alloc_cache.c| cache->elem_size, gfp                                    | kmalloc                    | alloc_cache.c     | function call
sizeof                     | alloc_cache.c| cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL) | sizeof                     | alloc_cache.c     | operator
sizeof                     | alloc_cache.c| cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL) | sizeof                     | alloc_cache.c     | operator
while                      | alloc_cache.c| entry = io_alloc_cache_get(cache)                        | while                      | alloc_cache.c     | loop
io_alloc_cache_get             | alloc_cache.c| cache                                                 | io_alloc_cache_get             | alloc_cache.c     | function call
sizeof                          | alloc_cache.c| max_nr, sizeof(void *), GFP_KERNEL                     | sizeof                          | alloc_cache.c     | keyword
sizeof                         | alloc_cache.c| max_nr, sizeof(void *), GFP_KERNEL                     | sizeof                         | alloc_cache.c    | keyword
while                           | alloc_cache.c| io_alloc_cache_get(cache)                              | while                           | alloc_cache.c    | loop
while                   | alloc_cache.c    | while ((entry = io_alloc_cache_get(cache)) != NULL)                               | while                     | alloc_cache.c          | keyword / control statement  
sizeof                 | alloc_cache.c              | sizeof(void *)                                                   | sizeof                 | alloc_cache.c                  | keyword   
while                  | alloc_cache.c              | while ((entry = io_alloc_cache_get(cache)) != NULL)              | while                   | alloc_cache.c                  | keyword  
sizeof                 | alloc_cache.c              | kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);               | sizeof                  | alloc_cache.c                 | keyword        
while                  | alloc_cache.c              | while ((entry = io_alloc_cache_get(cache)) != NULL)               | while                   | alloc_cache.c                 | keyword   
kmalloc                 | alloc_cache.c              | kmalloc(cache->elem_size, gfp)                                    | kmalloc                 | alloc_cache.c                   | function call 
while                   | alloc_cache.c              | while ((entry = io_alloc_cache_get(...))                          | while                   | alloc_cache.c                   | keyword 
kmalloc                     | alloc_cache.c | cache->elem_size, gfp                    | kmalloc                    | alloc_cache.c | function call
sizeof                      | alloc_cache.c | sizeof(void *)                           | sizeof                     | alloc_cache.c | keyword/operator
while                       | alloc_cache.c | while ((entry = ...))                    | while                      | alloc_cache.c | keyword
free                    | alloc_cache.c             | void (*free)(const void *)                                       | free                    | alloc_cache.c                 | function pointer 
sizeof                | alloc_cache.c              | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL); | sizeof                | alloc_cache.c              | function call               
while                 | alloc_cache.c              | while ((entry = io_alloc_cache_get(cache)) != NULL)               | while                 | alloc_cache.c              | loop   
sizeof                 | alloc_cache.c              | sizeof(void *)                                                    | sizeof                  | alloc_cache.c                   | macro
entries                | alloc_cache.c              | if (!cache->entries)                                            | entries                 | alloc_cache.c                   | macro  
io_alloc_cache_free    | alloc_cache.c              | void io_alloc_cache_free(struct io_alloc_cache *cache, ...)     | io_alloc_cache_free     | alloc_cache.c                   | function definition             
io_alloc_cache_init    | alloc_cache.c              | bool io_alloc_cache_init(struct io_alloc_cache *cache)          | io_alloc_cache_init     | alloc_cache.c                   | function definition  
kmalloc                        | alloc_cache.c      | obj = kmalloc(cache->elem_size, gfp);
kvfree                 | alloc_cache.c             | cache->entries                                                | kvfree                 | alloc_cache.c                  | function call
kvmalloc_array         | alloc_cache.c             | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL) | kvmalloc_array         | alloc_cache.c                  | function call
memset                 | alloc_cache.c             | memset(obj, 0, cache->init_clear)                              | memset                 | alloc_cache.c                  | function call
sizeof                 | alloc_cache.c             | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL) | sizeof                 | alloc_cache.c                  | operator
while                 | alloc_cache.c              | while ((entry = io_alloc_cache_get(cache)) != NULL)                | while                  | alloc_cache.c                 | loop statement  
kmalloc                 | alloc_cache.c              | obj = kmalloc(cache->elem_size, gfp);                                       | kmalloc                 | alloc_cache.c                  | function call
kvfree                  | alloc_cache.c              | kvfree(cache->entries);                                                    | kvfree                  | alloc_cache.c                  | function call
kvmalloc_array          | alloc_cache.c              | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);         | kvmalloc_array          | alloc_cache.c                  | function call
memset                  | alloc_cache.c              | memset(obj, 0, cache->init_clear);                                          | memset                  | alloc_cache.c                  | function call
sizeof                  | alloc_cache.c              | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);        | sizeof                  | alloc_cache.c                  | operator
kmalloc                 | alloc_cache.c              | obj = kmalloc(cache->elem_size, gfp);                                          | kmalloc                 | alloc_cache.c                | function call
sizeof                  | alloc_cache.c              | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);            | sizeof                  | alloc_cache.c                | operator
free                    | alloc_cache.c              | void (*free)(const void *))                                                  | free                    | alloc_cache.c                | function pointer
io_alloc_cache_free      | alloc_cache.c              | void io_alloc_cache_free(struct io_alloc_cache *cache,                        | io_alloc_cache_free      | alloc_cache.c                | function definition
io_alloc_cache_get       | alloc_cache.c              | while ((entry = io_alloc_cache_get(cache)) != NULL)                            | io_alloc_cache_get       | alloc_cache.c                | function call
io_alloc_cache_init      | alloc_cache.c              | bool io_alloc_cache_init(struct io_alloc_cache *cache,                        | io_alloc_cache_init      | alloc_cache.c                | function definition
io_cache_alloc_new       | alloc_cache.c              | void *io_cache_alloc_new(struct io_alloc_cache *cache, gfp_t gfp)              | io_cache_alloc_new       | alloc_cache.c                | function definition
kmalloc                 | alloc_cache.c              | obj = kmalloc(cache->elem_size, gfp);                                          | kmalloc                 | alloc_cache.c                | function call
kvfree                  | alloc_cache.c              | kvfree(cache->entries);                                                       | kvfree                  | alloc_cache.c                | function call
kvmalloc_array          | alloc_cache.c              | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);           | kvmalloc_array          | alloc_cache.c                | function call
memset                  | alloc_cache.c              | memset(obj, 0, cache->init_clear);                                             | memset                  | alloc_cache.c                | function call
sizeof                  | alloc_cache.c              | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);           | sizeof                  | alloc_cache.c                | operator
void                    | alloc_cache.c              | void io_alloc_cache_free(struct io_alloc_cache *cache,                        | void                    | alloc_cache.c                | return type
while                   | alloc_cache.c              | while ((entry = io_alloc_cache_get(cache)) != NULL)                            | while                   | alloc_cache.c                | loop
kmalloc                 | alloc_cache.c              | obj = kmalloc(cache->elem_size, gfp);                                          | kmalloc                 | alloc_cache.c                | function call
kvfree                  | alloc_cache.c              | kvfree(cache->entries);                                                       | kvfree                  | alloc_cache.c                | function call
sizeof                  | alloc_cache.c              | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);           | sizeof                  | alloc_cache.c                | operator
memset                  | alloc_cache.c             | memset(obj, 0, cache->init_clear);                                           | memset                  | alloc_cache.c                | function call
sizeof                | alloc_cache.c              | void *                                                          | sizeof                 | alloc_cache.c                   | operator     
while                 | alloc_cache.c              | io_alloc_cache_get(cache)                                       | while                  | alloc_cache.c                   | loop   
kvfree                  | alloc_cache.c    | kvfree(cache->entries)                                          | kvfree                  | alloc_cache.c                   | function call   
kvmalloc_array          | alloc_cache.c    | kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL)             | kvmalloc_array          | alloc_cache.c                   | function call    
memset                  | alloc_cache.c    | memset(obj, 0, cache->init_clear)                               | memset                  | alloc_cache.c                   | function call 
sizeof                  | alloc_cache.c    | sizeof(void *)                                                  | sizeof                  | alloc_cache.c                   | macro  
while                   | alloc_cache.c    | while ((entry = io_alloc_cache_get(cache)) != NULL)           | while                   | alloc_cache.c                   | keyword 
void                       | alloc_cache.c             | void io_alloc_cache_free(struct io_alloc_cache *cache)                       | void                       | alloc_cache.c                 | function definition     
io_alloc_cache_free     | alloc_cache.c             | void io_alloc_cache_free(struct io_alloc_cache *cache)                      | io_alloc_cache_free     | alloc_cache.c                | function definition             
io_alloc_cache_init     | alloc_cache.c             | bool io_alloc_cache_init(struct io_alloc_cache *cache)                      | io_alloc_cache_init     | alloc_cache.c                | function definition
sizeof                 | alloc_cache.c             | cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);         | sizeof                 | alloc_cache.c                | operator call                   
io_alloc_cache_free | alloc_cache.h | struct io_alloc_cache* cache | io_alloc_cache_free | io_uring/alloc_cache.h | function to free cache
io_alloc_cache_init | alloc_cache.h | struct io_alloc_cache* cache | io_alloc_cache_init | io_uring/alloc_cache.h | function to initialize cache
io_cache_alloc_new | alloc_cache.h | struct io_alloc_cache* cache, gfp_t gfp | io_cache_alloc_new | io_uring/alloc_cache.h | function to allocate new cache
io_alloc_cache_kasan | alloc_cache.h | struct iovec** iov, int* nr | io_alloc_cache_kasan | io_uring/alloc_cache.h | function for kasan cache allocation
io_alloc_cache_put | alloc_cache.h | struct io_alloc_cache* cache | io_alloc_cache_put | io_uring/alloc_cache.h | function to put cache object
io_alloc_cache_get | alloc_cache.h | struct io_alloc_cache* cache | io_alloc_cache_get | io_uring/alloc_cache.h | function to get cache object
io_cache_alloc | alloc_cache.h | struct io_alloc_cache* cache, gfp_t gfp | io_cache_alloc | io_uring/alloc_cache.h | function to allocate from cache
copy_from_user          | cancel.c                  | sc, arg, sizeof(sc)                                              | copy_from_user          | cancel.c                         | function parameter                
io_ring_submit_lock     | cancel.c                  | ctx, issue_flags                                                   | io_ring_submit_lock       | cancel.c                         | function parameter                
io_ring_submit_unlock   | cancel.c                  | ctx, issue_flags                                                   | io_ring_submit_unlock     | cancel.c                         | function parameter                
spin_lock               | cancel.c                  | ctx->completion_lock                                               | spin_lock                 | cancel.c                         | function parameter                
spin_unlock             | cancel.c                  | ctx->completion_lock                                               | spin_unlock               | cancel.c                         | function parameter                
unlikely                | cancel.c                  | req->flags & REQ_F_BUFFER_SELECT                                  | unlikely                  | cancel.c                         | function parameter   
io_slot_file          | cancel.c                   | cd->file                                                          | io_slot_file            | cancel.c                        | function definition
list_for_each_entry   | cancel.c                   | node, ctx->tctx_list, ctx_node                                     | list_for_each_entry     | cancel.c                        | function definition
mutex_unlock          | cancel.c                   | ctx->uring_lock                                                    | mutex_unlock            | cancel.c                        | function definition
spin_unlock            | cancel.c                   | &ctx->completion_lock                                            | spin_unlock             | cancel.c                        | function call
io_file_get_fixed      | cancel.c                   | req, cancel->fd                                                   | io_file_get_fixed       | cancel.c                        | function call
io_file_get_normal     | cancel.c                   | req, cancel->fd                                                   | io_file_get_normal      | cancel.c                        | function call
io_ring_submit_lock    | cancel.c                   | ctx, issue_flags                                                  | io_ring_submit_lock     | cancel.c                        | function call
io_ring_submit_unlock  | cancel.c                   | ctx, issue_flags                                                  | io_ring_submit_unlock   | cancel.c                        | function call
io_rsrc_node_lookup    | cancel.c                   | &ctx->file_table.data, fd  
container_of              | cancel.c     | work, struct io_kiocb, work                            | container_of              | cancel.c          | macro
io_ring_submit_lock       | cancel.c     | ctx, issue_flags                                        | io_ring_submit_lock       | cancel.c          | function call
io_ring_submit_unlock     | cancel.c     | ctx, issue_flags                                        | io_ring_submit_unlock     | cancel.c          | function call
io_rsrc_node_lookup       | cancel.c     | &ctx->file_table.data, fd                           | io_rsrc_node_lookup       | cancel.c          | function call
s                         | cancel.c     | slow path comment                                    | s                        | cancel.c          | comment
unlikely                  | cancel.c     | req->flags & REQ_F_BUFFER_SELECT                      | unlikely                  | cancel.c          | macro
container_of               | cancel.c     | work, struct io_kiocb, work                              | container_of               | cancel.c          | macro
copy_from_user             | cancel.c     | &sc, arg, sizeof(sc)                                     | copy_from_user             | cancel.c          | function call
fput                       | cancel.c     | file                                                    | fput                       | cancel.c          | function call
io_ring_submit_lock        | cancel.c     | ctx, issue_flags                                          | io_ring_submit_lock        | cancel.c          | function call
io_ring_submit_unlock      | cancel.c     | ctx, issue_flags                                          | io_ring_submit_unlock      | cancel.c          | function call
io_waitid_cancel          | cancel.c     | ctx, cd, issue_flags                                    | io_waitid_cancel          | cancel.c          | function call
io_wq_current_is_worker    | cancel.c     | tctx != current->io_uring                               | io_wq_current_is_worker    | cancel.c          | function call
spin_lock                  | cancel.c     | &ctx->completion_lock                                    | spin_lock                  | cancel.c          | function call
spin_unlock                | cancel.c     | &ctx->completion_lock                                    | spin_unlock                | cancel.c          | function call
container_of                   | cancel.c     | work, struct io_kiocb, work                             | container_of                   | cancel.c         | macro
copy_from_user                 | cancel.c     | &sc, arg, sizeof(sc)                                    | copy_from_user                 | cancel.c         | function call
DEFINE_WAIT                     | cancel.c     | wait                                                   | DEFINE_WAIT                     | cancel.c         | macro
fget                            | cancel.c     | sc.fd                                                   | fget                            | cancel.c         | function call
finish_wait                    | cancel.c     | &ctx->cq_wait, &wait                                   | finish_wait                    | cancel.c         | function call
fput                           | cancel.c     | file                                                   | fput                           | cancel.c         | function call
__io_async_cancel              | cancel.c     | cd                                                     | __io_async_cancel              | cancel.c         | function call
io_async_cancel                | cancel.c     | req, issue_flags                                        | io_async_cancel                | cancel.c         | function call
io_async_cancel_one            | cancel.c     | tctx, cd                                                | io_async_cancel_one            | cancel.c         | function call
io_async_cancel_prep           | cancel.c     | req, sqe                                                | io_async_cancel_prep           | cancel.c         | function call
io_cancel_cb                   | cancel.c     | work, data                                              | io_cancel_cb                   | cancel.c         | function call
io_cancel_match_sequence       | cancel.c     | req, cd->seq                                            | io_cancel_match_sequence       | cancel.c         | function call
io_cancel_req_match            | cancel.c     | req, cd                                                 | io_cancel_req_match            | cancel.c         | function call
io_cancel_req_match    | cancel.c                  | bool io_cancel_req_match(struct io_kiocb *req, struct io_cancel_data *cd)  | io_cancel_req_match     | cancel.c                       | function definition
io_file_get_fixed              | cancel.c     | req, cancel->fd,                                        | io_file_get_fixed              | cancel.c         | function call
io_file_get_normal             | cancel.c     | req, cancel->fd                                         | io_file_get_normal             | cancel.c         | function call
io_futex_cancel                | cancel.c     | ctx, cd, issue_flags                                    | io_futex_cancel                | cancel.c         | function call
io_poll_cancel                 | cancel.c     | ctx, cd, issue_flags                                    | io_poll_cancel                 | cancel.c         | function call
io_ring_submit_lock           | cancel.c     | ctx, issue_flags                                        | io_ring_submit_lock           | cancel.c         | function call
io_ring_submit_unlock         | cancel.c     | ctx, issue_flags                                        | io_ring_submit_unlock         | cancel.c         | function call
io_rsrc_node_lookup           | cancel.c     | &ctx->file_table.data, fd                               | io_rsrc_node_lookup           | cancel.c         | function call
io_run_task_work_sig          | cancel.c     | ctx                                                   | io_run_task_work_sig          | cancel.c         | function call
io_slot_file                  | cancel.c     | node                                                   | io_slot_file                  | cancel.c         | function call
io_timeout_cancel              | cancel.c     | ctx, cd                                                 | io_timeout_cancel              | cancel.c         | function call
io_try_cancel                  | cancel.c     | tctx, cd                                                | io_try_cancel                  | cancel.c         | function call
io_try_cancel          | cancel.c                  | int io_try_cancel(struct io_uring_task *tctx, struct io_cancel_data *cd)    | io_try_cancel           | cancel.c                       | function definition
io_waitid_cancel               | cancel.c     | ctx, cd, issue_flags                                    | io_waitid_cancel               | cancel.c         | function call
io_wq_cancel_cb                | cancel.c     | tctx->io_wq, io_cancel_cb, cd, all                      | io_wq_cancel_cb                | cancel.c         | function call
io_wq_current_is_worker        | cancel.c     | tctx != current->io_uring                              | io_wq_current_is_worker        | cancel.c         | function call
ktime_add_ns                   | cancel.c     | timespec64_to_ktime(ts), ktime_get_ns()                | ktime_add_ns                   | cancel.c         | function call
ktime_get_ns                   | cancel.c     |                                                     | ktime_get_ns                   | cancel.c         | function call
list_for_each_entry            | cancel.c     | node, &ctx->tctx_list, ctx_node                        | list_for_each_entry            | cancel.c         | macro
__must_hold                    | cancel.c     | &ctx->uring_lock                                       | __must_hold                    | cancel.c         | macro
mutex_lock                     | cancel.c     | &ctx->uring_lock                                       | mutex_lock                     | cancel.c         | function call
mutex_unlock                   | cancel.c     | &ctx->uring_lock                                       | mutex_unlock                   | cancel.c         | function call
prepare_to_wait                | cancel.c     | &ctx->cq_wait, &wait, TASK_INTERRUPTIBLE                | prepare_to_wait                | cancel.c         | function call
schedule_hrtimeout             | cancel.c     | &timeout, HRTIMER_MODE_ABS                             | schedule_hrtimeout             | cancel.c         | function call
spin_lock                      | cancel.c     | &ctx->completion_lock                                  | spin_lock                      | cancel.c         | function call
spin_unlock                    | cancel.c     | &ctx->completion_lock                                  | spin_unlock                    | cancel.c         | function call
timespec64_to_ktime            | cancel.c     | ts, ktime_get_ns()                                     | timespec64_to_ktime            | cancel.c         | function call
unlikely                       | cancel.c     | req->flags & REQ_F_BUFFER_SELECT                       | unlikely                       | cancel.c         | keyword
ARRAY_SIZE                     | cancel.c     | sc.pad                                                 | ARRAY_SIZE                     | cancel.c         | macro
atomic_inc_return              | cancel.c     | req->ctx->cancel_seq                                    | atomic_inc_return              | cancel.c         | function call
CANCEL_FLAGS                   | cancel.c     | IORING_ASYNC_CANCEL_ALL, IORING_ASYNC_CANCEL_FD         | CANCEL_FLAGS                   | cancel.c         | macro
container_of           | cancel.c                     | container_of(work, struct io_kiocb, work)           | container_of            | cancel.c                       | macro
copy_from_user         | cancel.c                     | copy_from_user(&sc, arg, sizeof(sc))                | copy_from_user          | cancel.c                       | function call
unlikely               | cancel.c                   | unlikely(req->flags & REQ_F_BUFFER_SELECT)                       | unlikely                | cancel.c                       | macro
until                  | cancel.c                   | Keep looking until ...                                           | until                   | cancel.c                       | comment context
u64_to_user_ptr           | epoll.c      | READ_ONCE(sqe->addr)                                   | u64_to_user_ptr           | epoll.c           | function call
u64_to_user_ptr         | epoll.c                   | sqe->addr                                                         | 
u64_to_user_ptr           | epoll.c                          | function parameter                
mode                   | epoll.c                    | issue_flags, non-blocking mode                  
common_tracking_show_fdinfo | fdinfo.c               | ctx->ring_ctx                                                     | common_tracking_show_fdinfo | fdinfo.c                    | function definition
from_kgid_munged      | fdinfo.c                   | cred->gid                                                          | from_kgid_munged        | fdinfo.c                        | function definition
from_kuid_munged      | fdinfo.c                   | cred->uid                                                          | from_kuid_munged        | fdinfo.c                        | function definition
getrusage              | fdinfo.c                   | sq->thread, RUSAGE_SELF                                            | getrusage               | fdinfo.c                        | function definition
hlist_for_each_entry   | fdinfo.c                   | req, hb->list, hash_node                                           | hlist_for_each_entry    | fdinfo.c                        | function definition
io_uring_get_opcode   | fdinfo.c                   | sq_idx, io_uring_get_opcode(sqe->opcode), sqe->fd                  | io_uring_get_opcode     | fdinfo.c                        | function definition
io_uring_show_cred    | fdinfo.c                   | m, id                                                             | io_uring_show_cred      | fdinfo.c                        | function definition
io_uring_show_fdinfo  | fdinfo.c                   | m, file                                                           | io_uring_show_fdinfo    | fdinfo.c                        | function definition
min                    | fdinfo.c                   | sq_tail - sq_head, ctx->sq_entries                                 | min                     | fdinfo.c                        | function definition
mutex_trylock         | fdinfo.c                   | ctx->uring_lock                                                    | mutex_trylock           | fdinfo.c                        | function definition
napi_show_fdinfo      | fdinfo.c                   | ctx->ring_ctx                                                     | napi_show_fdinfo        | fdinfo.c                        | function definition
seq_file_path         | fdinfo.c                   | m, f, " \t\n\\"                                                    | seq_file_path           | fdinfo.c                        | function definition
seq_printf            | fdinfo.c                   | m, "%5d\n", id                                                     | seq_printf              | fdinfo.c                        | function definition
seq_putc              | fdinfo.c                   | m, '\n'                                                           | seq_putc                | fdinfo.c                        | function definition
seq_put_decimal_ull   | fdinfo.c                   | m, "\tUid:\t", from_kuid_munged(uns, cred->uid)                    | seq_put_decimal_ull     | fdinfo.c                        | function definition
seq_put_hex_ll        | fdinfo.c                   | m, NULL, cap.val, 16                                               | seq_put_hex_ll          | fdinfo.c                        | function definition
seq_puts              | fdinfo.c                   | m, "\n\tGroups:\t"                                                 | seq_puts                | fdinfo.c                        | function definition
seq_user_ns           | fdinfo.c                   | uns = seq_user_ns(m)                                               | seq_user_ns             | fdinfo.c                        | function definition
task_work_pending      | fdinfo.c                   | req->tctx->task                                                   | task_work_pending       | fdinfo.c                        | function call
xa_empty               | fdinfo.c                   | !xa_empty(&ctx->personalities)                                    | xa_empty                | fdinfo.c                        | function call
xa_for_each            | fdinfo.c                   | &ctx->personalities, index, cred                                  | xa_for_each             | fdinfo.c                        | function call
min                       | fdinfo.c     | sq_tail - sq_head, ctx->sq_entries                   | min                       | fdinfo.c          | macro
io_fixed_fd_install    | filetable.c                | error value, fd                                                    | io_fixed_fd_install     | filetable.c                     | function definition
check_add_overflow      | filetable.c          | range.off, range.len, &end                                       | check_add_overflow      | filetable.c          | function call
bitmap_free                | filetable.c  | table->bitmap                                            | bitmap_free                | filetable.c       | function call
bitmap_zalloc              | filetable.c  | nr_files, GFP_KERNEL_ACCOUNT                             | bitmap_zalloc              | filetable.c       | function call
check_add_overflow         | filetable.c  | range.off, range.len, &end                               | check_add_overflow         | filetable.c       | function call
find_next_zero_bit         | filetable.c  | table->bitmap, nr, table->alloc_hint                     | find_next_zero_bit         | filetable.c       | function call
__io_fixed_fd_install      | filetable.c  | ctx, file                                                | __io_fixed_fd_install      | filetable.c       | function definition
io_alloc_file_tables       | filetable.c  | ctx, table                                               | io_alloc_file_tables       | filetable.c       | function definition
io_file_bitmap_clear       | filetable.c  | &ctx->file_table, offset                                 | io_file_bitmap_clear       | filetable.c       | function call
io_file_bitmap_get         | filetable.c  | ctx                                                     | io_file_bitmap_get         | filetable.c       | function call
io_file_bitmap_set         | filetable.c  | &ctx->file_table, slot_index                             | io_file_bitmap_set         | filetable.c       | function call
io_file_table_set_alloc_range | filetable.c | ctx, range.off, range.len                                | io_file_table_set_alloc_range | filetable.c    | function call
io_fixed_fd_install        | filetable.c  | error value                                             | io_fixed_fd_install        | filetable.c       | function call
io_fixed_fd_remove         | filetable.c  | ctx, offset                                              | io_fixed_fd_remove         | filetable.c       | function definition
io_fixed_file_set          | filetable.c  | node, file                                               | io_fixed_file_set          | filetable.c       | function call
io_free_file_tables        | filetable.c  | ctx, table                                               | io_free_file_tables        | filetable.c       | function definition
io_install_fixed_file      | filetable.c  | ctx, file                                                | io_install_fixed_file      | filetable.c       | function call
io_is_uring_fops           | filetable.c  | file                                                    | io_is_uring_fops           | filetable.c       | function call
io_register_file_alloc_range | filetable.c | ctx, ...                                                 | io_register_file_alloc_range | filetable.c    | function call
io_reset_rsrc_node         | filetable.c  | ctx, &ctx->file_table.data, slot_index                   | io_reset_rsrc_node         | filetable.c       | function call
io_rsrc_data_alloc         | filetable.c  | &table->data, nr_files                                    | io_rsrc_data_alloc         | filetable.c       | function call
io_rsrc_data_free          | filetable.c  | ctx, &table->data                                         | io_rsrc_data_free          | filetable.c       | function definition
io_rsrc_data_free          | filetable.c       | function call
io_rsrc_node_alloc         | filetable.c  | IORING_RSRC_FILE                                          | io_rsrc_node_alloc         | filetable.c       | function call
io_is_uring_fops               | filetable.c  | file                                                  | io_is_uring_fops               | filetable.c       | function call
__io_fixed_fd_install          | filetable.c  | ctx, file                                              | __io_fixed_fd_install          | filetable.c       | function call
getname_uflags               | fs.c         | oldf, lnk->flags                                         | getname_uflags               | fs.c              | function call
putname                      | fs.c         | ren->oldpath                                             | putname                      | fs.c              | function call
do_linkat              | fs.c                         | do_linkat(lnk->old_dfd, ...)                        | do_linkat               | fs.c                           | function call
do_mkdirat             | fs.c                         | do_mkdirat(mkd->dfd, ...)                           | do_mkdirat              | fs.c                           | function call
do_renameat2           | fs.c                         | do_renameat2(ren->old_dfd, ...)                     | do_renameat2            | fs.c                           | function call
do_rmdir               | fs.c                         | do_rmdir(un->dfd, ...)                              | do_rmdir                | fs.c                           | function call
do_symlinkat           | fs.c                         | do_symlinkat(sl->oldpath, ...)                      | do_symlinkat            | fs.c                           | function call
do_unlinkat            | fs.c                         | do_unlinkat(un->dfd, ...)                           | do_unlinkat             | fs.c                           | function call
getname                | fs.c                         | getname(oldf)                                       | getname                 | fs.c                           | function call
getname_uflags         | fs.c                         | getname_uflags(oldf, flags)                         | getname_uflags          | fs.c                           | function call
io_link_cleanup        | fs.c                         | io_link_cleanup(req)                                | io_link_cleanup         | fs.c                           | function definition
io_linkat              | fs.c                         | io_linkat(req, flags)                               | io_linkat               | fs.c                           | function definition
io_linkat_prep         | fs.c                         | io_linkat_prep(req, sqe)                            | io_linkat_prep          | fs.c                           | function definition
io_mkdirat             | fs.c                         | io_mkdirat(req, flags)                              | io_mkdirat              | fs.c                           | function definition
io_mkdirat_cleanup     | fs.c                         | io_mkdirat_cleanup(req)                             | io_mkdirat_cleanup      | fs.c                           | function definition
io_mkdirat_prep        | fs.c                         | io_mkdirat_prep(req, sqe)                           | io_mkdirat_prep         | fs.c                           | function definition
io_renameat            | fs.c                         | io_renameat(req, flags)                             | io_renameat             | fs.c                           | function definition
io_renameat_cleanup    | fs.c                         | io_renameat_cleanup(req)                            | io_renameat_cleanup     | fs.c                           | function definition
io_renameat_prep       | fs.c                         | io_renameat_prep(req, sqe)                          | io_renameat_prep        | fs.c                           | function definition
io_symlinkat           | fs.c                         | io_symlinkat(req, flags)                            | io_symlinkat            | fs.c                           | function definition
io_symlinkat_prep      | fs.c                         | io_symlinkat_prep(req, sqe)                         | io_symlinkat_prep       | fs.c                           | function definition
io_unlinkat            | fs.c                         | io_unlinkat(req, flags)                             | io_unlinkat             | fs.c                           | function definition
io_unlinkat_cleanup    | fs.c                         | io_unlinkat_cleanup(req)                            | io_unlinkat_cleanup     | fs.c                           | function definition
io_unlinkat_prep       | fs.c                         | io_unlinkat_prep(req, sqe)                          | io_unlinkat_prep        | fs.c                           | function definition
putname                | fs.c                         | putname(ren->oldpath)                               | putname                 | fs.c                           | function call
lockdep_assert_held     | futex.c                   | ctx->uring_lock                                                   | lockdep_assert_held       | futex.c                          | function parameter                
hlist_del_init            | futex.c      | &req->hash_node                                        | hlist_del_init            | futex.c           | function call
hlist_for_each_entry_safe | futex.c      | req, tmp, &ctx->futex_list, hash_node                 | hlist_for_each_entry_safe | futex.c           | function call
io_match_task_safe        | futex.c      | req, tctx, cancel_all                                  | io_match_task_safe        | futex.c           | function call
io_req_task_complete      | futex.c      | req, ts                                                | io_req_task_complete      | futex.c           | function call
io_req_task_work_add      | futex.c      | req                                                    | io_req_task_work_add      | futex.c           | function call
io_tw_lock             | futex.c                   | io_tw_lock(ctx, ts)                                                      | io_tw_lock              | futex.c                        | function call
io_req_task_complete   | futex.c                   | io_req_task_complete(req, ts)                                             | io_req_task_complete    | futex.c                        | function call
io_req_task_work_add   | futex.c                   | io_req_task_work_add(req)                                                 | io_req_task_work_add    | futex.c                        | function call
__set_current_state    | futex.c                    | __set_current_state(TASK_RUNNING)                                | __set_current_state     | futex.c                        | macro/function
io_req_task_complete   | futex.c                      | req, ts                                             | io_req_task_complete    | futex.c                        | function call
lockdep_assert_held    | futex.c                    | lockdep_assert_held(&ctx->uring_lock)                            | lockdep_assert_held     | futex.c                        | macro
successful             | futex.c                    | successful setup, then the task ...                              | successful              | futex.c                        | comment context
atomic_or                 | io-wq.c      | IO_WQ_WORK_CANCEL, &work->flags                        | atomic_or                 | io-wq.c           | function call
atomic_read               | io-wq.c      | &work->flags                                           | atomic_read               | io-wq.c           | function call
list_del_init              | io-wq.c      | &wq->wait.entry                                          | list_del_init              | io-wq.c           | function call
spin_lock_irq              | io-wq.c      | &wq->hash->wait.lock                                     | spin_lock_irq              | io-wq.c           | function call
spin_unlock_irq            | io-wq.c      | &wq->hash->wait.lock                                     | spin_unlock_irq            | io-wq.c           | function call
init_task_work                 | io-wq.c      | &worker->create_work, func                            | init_task_work                 | io-wq.c           | function call
BUILD_BUG_ON                    | io-wq.c      | (int) IO_WQ_ACCT_BOUND != (int) IO_WQ_BOUND             | BUILD_BUG_ON                    | io-wq.c           | macro
ERR_PTR                | io-wq.c                   | return ERR_PTR(-EINVAL)                                                  | ERR_PTR                 | io-wq.c                        | function call
INIT_LIST_HEAD         | io-wq.c                   | INIT_LIST_HEAD(&wq->wait.entry)                                           | INIT_LIST_HEAD          | io-wq.c                        | macro
list_del_init          | io-wq.c                   | list_del_init(&wq->wait.entry)                                            | list_del_init           | io-wq.c                        | function call
list_empty             | io-wq.c                   | if (list_empty(&wq->wait.entry))                                          | list_empty              | io-wq.c                        | function call
atomic_read            | io-wq.c                   | return io_get_acct(wq, !(atomic_read(&work->flags) & IO_WQ_WORK_UNBOUND))   | atomic_read             | io-wq.c                        | function call
complete               | io-wq.c                      | complete(&worker->ref_done)                         | complete                | io-wq.c                        | function call
INIT_LIST_HEAD         | io-wq.c                      | INIT_LIST_HEAD(&wq->wait.entry)                     | INIT_LIST_HEAD          | io-wq.c                        | macro
likely                 | io-wq.c                    | Most likely an attempt ...                                       | likely                  | io-wq.c                        | macro
list_del_init          | io-wq.c                    | list_del_init(&wq->wait.entry)                                   | list_del_init           | io-wq.c                        | function call
set_current_state      | io-wq.c                    | set_current_state(TASK_INTERRUPTIBLE)                            | set_current_state       | io-wq.c                        | function call
wq_list_cut            | io-wq.c                    | wq_list_cut(&acct->work_list, ...)                               | wq_list_cut             | io-wq.c                        | function call
wq_list_empty          | io-wq.c                    | !wq_list_empty(&acct->work_list)                                 | wq_list_empty           | io-wq.c                        | function call
wq_list_for_each       | io-wq.c                    | wq_list_for_each(node, prev, ...)                                | wq_list_for_each        | io-wq.c                        | macro
BUG_ON                          | io_uring.c   | !tctx                                                 | BUG_ON                          | io_uring.c        | macro
io_add_aux_cqe                 | io_uring.c   | ctx, user_data, res, cflags                           | io_add_aux_cqe                 | io_uring.c        | function call
io_post_aux_cqe                | io_uring.c   | ctx, user_data, res, cflags                           | io_post_aux_cqe                | io_uring.c        | function call
PAGE_ALIGN                | io_uring.c   | size                                                 | PAGE_ALIGN               | io_uring.c        | macro
hlist_add_head            | io_uring.c   | user_access_end()                                      | hlist_add_head            | io_uring.c        | function call
init_waitqueue_func_entry | io_uring.c   | &iowq.wq, io_wake_function                            | init_waitqueue_func_entry | io_uring.c        | function call
io_req_post_cqe           | io_uring.c   | req, res, cflags                                    | io_req_post_cqe           | io_uring.c        | function definition
unsafe_get_user           | io_uring.c   | arg.sigmask, &uarg->sigmask, uaccess_end               | unsafe_get_user           | io_uring.c        | function call
user_access_begin         | io_uring.c   | uarg, sizeof(*uarg)                                    | user_access_begin         | io_uring.c        | function call
io_uring_optable_init           | io_uring.c   |                                                     | io_uring_optable_init           | io_uring.c        | function call
kmem_cache_alloc               | io_uring.c   | req_cachep, gfp                                         | kmem_cache_alloc               | io_uring.c        | function call
kmem_cache_free                | io_uring.c   | req_cachep, req                                         | kmem_cache_free                | io_uring.c        | function call
percpu_ref_get                 | io_uring.c   | ctx->refs                                               | percpu_ref_get                 | io_uring.c        | function call
percpu_ref_put                 | io_uring.c   | ctx->refs                                               | percpu_ref_put                 | io_uring.c        | function call
prep                            | io_uring.c   | linked timeouts should have two refs once prep'ed      | prep                            | io_uring.c        | comment
io_disarm_next         | io-uring.c                | /* requests with any of those set should undergo io_disarm_next() */       | io_disarm_next          | io-uring.c                     | function call
io_flush_timeouts      | io-uring.c                | io_flush_timeouts(ctx)                                                    | io_flush_timeouts       | io-uring.c                     | function call
io_for_each_link       | io-uring.c                | io_for_each_link(req, head)                                               | io_for_each_link        | io-uring.c                     | function call
io_free_req            | io-uring.c                | __cold void io_free_req(struct io_kiocb *req)                              | io_free_req             | io-uring.c                     | function call
io_kill_timeouts       | io-uring.c                | ret |= io_kill_timeouts(ctx, tctx, cancel_all);                           | io_kill_timeouts        | io-uring.c                     | function call
io_match_task          | io-uring.c                | * As io_match_task() but protected against racing with linked timeouts.     | io_match_task           | io-uring.c                     | function call
io_queue_linked_timeout | io-uring.c               | io_queue_linked_timeout(__io_prep_linked_timeout(req))                     | io_queue_linked_timeout  | io-uring.c                     | function call
io_queue_next          | io-uring.c                | void io_queue_next(struct io_kiocb *req)                                   | io_queue_next           | io-uring.c                     | function call
io_req_post_cqe        | io-uring.c                | bool io_req_post_cqe(struct io_kiocb *req, s32 res, u32 cflags)           | io_req_post_cqe         | io-uring.c                     | function call
io_should_terminate_tw | io-uring.c                | if (unlikely(io_should_terminate_tw()))                                    | io_should_terminate_tw  | io-uring.c                     | function call
LIST_HEAD              | io-uring.c                | LIST_HEAD(list)                                                           | LIST_HEAD               | io_uring.c                     | macro
list_add_tail          | io-uring.c                | list_add_tail(&ocqe->list, &ctx->cq_overflow_list)                        | list_add_tail           | io-uring.c                     | function call
list_del               | io-uring.c                | list_del(&ocqe->list)                                                     | list_del                | io-uring.c                     | function call
list_first_entry       | io-uring.c                | struct io_defer_entry *de = list_first_entry(&ctx->defer_list)            | list_first_entry        | io_uring.c                     | function call
raw_spin_lock_irq      | io-uring.c                | raw_spin_lock_irq(&ctx->timeout_lock)                                     | raw_spin_lock_irq       | io_uring.c                     | function call
raw_spin_unlock_irq    | io-uring.c                | raw_spin_unlock_irq(&ctx->timeout_lock)                                   | raw_spin_unlock_irq     | io_uring.c                     | function call
get_timespec64         | io-uring.c                | if (get_timespec64(&ext_arg->ts, u64_to_user_ptr(arg.ts)))                | get_timespec64          | io-uring.c                     | function call
destroy_hrtimer_on_stack | io_uring.c                | destroy_hrtimer_on_stack(&iowq->t)                  | destroy_hrtimer_on_stack | io_uring.c                   | function call
file_inode             | io_uring.c                   | file_inode(req->file)                               | file_inode              | io_uring.c                     | function call
hrtimer_cancel         | io_uring.c                   | hrtimer_cancel(&iowq->t)                            | hrtimer_cancel          | io_uring.c                     | function call
hrtimer_set_expires    | io_uring.c                   | hrtimer_set_expires(timer, ...)                     | hrtimer_set_expires     | io_uring.c                     | function call
io_do_iopoll           | io_uring.c                   | io_do_iopoll(ctx, true)                             | io_do_iopoll            | io_uring.c                     | function call
io_file_can_poll       | io_uring.c                   | io_file_can_poll(req, ...)                          | io_file_can_poll        | io_uring.c                     | function call
io_kbuf_recycle         | io_uring.c                | io_kbuf_recycle(req, 0)                                          | io_kbuf_recycle         | io_uring.c                     | function call
io_put_kbuf             | io_uring.c                | io_req_set_res(req, res, io_put_kbuf(...))                       | io_put_kbuf             | io_uring.c                     | function call
io_req_post_cqe        | io_uring.c                   | struct io_kiocb *req, s32 res, u32 cflags           | io_req_post_cqe         | io_uring.c                     | function definition
io_req_task_queue      | io_uring.c                   | de->req                                             | io_req_task_queue       | io_uring.c                     | function call
io_rw_cache_free       | io_uring.c                   | io_alloc_cache_free(...)                            | io_rw_cache_free        | io_uring.c                     | function reference
iopoll                  | io_uring.c                   | ctx->flags & IORING_SETUP_IOPOLL                                 | iopoll                  | io_uring.c                     | condition flag (bitfield)
S_ISBLK                | io_uring.c                 | !S_ISBLK(file_inode(req->file)->i_mode)                          | S_ISBLK                 | io_uring.c                     | macro
S_ISREG                | io_uring.c                 | S_ISREG(file_inode(file)->i_mode)                                | S_ISREG                 | io_uring.c                     | macro
smp_load_acquire       | io_uring.c                 | smp_load_acquire to read the tail                                | smp_load_acquire        | io_uring.c                     | macro
smp_store_release      | io_uring.c                 | smp_store_release to                                             | smp_store_release       | io_uring.c                     | macro
__io_req_task_work_add | io_uring.c                   | void __io_req_task_work_add(...)                    | __io_req_task_work_add  | io_uring.c                     | function definition
struct io_buffer        | kbuf.c                    | buffer data, flags, memory                                       | io_add_buffers            | kbuf.c                           | function parameter, local variable
struct io_buffer_list   | kbuf.c                    | memory region, buffer data, refcount                              | io_buffer_get_list        | kbuf.c                           | local variable                    
struct io_ring_ctx      | kbuf.c                    | context, number of buffers                                        | io_buffer_select          | kbuf.c                           | return value, local variable      
io_kbuf_commit          | kbuf.c                    | req, bl, len, flags                                                | io_kbuf_commit            | kbuf.c                           | function parameter                
io_kbuf_recycle_legacy  | kbuf.c                    | req, issue_flags                                                   | io_kbuf_recycle_legacy    | kbuf.c                           | function parameter                
kmalloc_array           | kbuf.c                    | nr_avail, size                                                   | kmalloc_array             | kbuf.c                           | function parameter                
list_add                | kbuf.c                    | buf, bl                                                           | list_add                  | kbuf.c                           | function parameter                
list_entry              | kbuf.c                    | item, io_buffer                                                    | list_entry                | kbuf.c                           | function parameter                
list_for_each_safe      | kbuf.c                    | item, tmp, ctx->io_buffers_cache                                   | list_for_each_safe        | kbuf.c                           | function parameter                
list_move               | kbuf.c                    | nxt, ctx->io_buffers_cache                                        | list_move                 | kbuf.c                           | function parameter                
list_move_tail          | kbuf.c                    | buf, bl                                                           | list_move_tail            | kbuf.c                           | function parameter                
list_splice_init        | kbuf.c                    | ctx->io_buffers_comp, ctx->io_buffers_cache                       | list_splice_init          | kbuf.c                           | function parameter                
MAX_BIDS_PER_BGID       | kbuf.c                    | (1 << 16)                                                         | MAX_BIDS_PER_BGID         | kbuf.c                           | macro                             
min_not_zero            | kbuf.c                    | needed                                                            | min_not_zero              | kbuf.c                           | function parameter                
min_t                   | kbuf.c                    | tail, head, UIO_MAXIOV                                            | min_t                     | kbuf.c                           | function parameter                
io_pbuf_get_region      | kbuf.c                    | ctx, region                                                      | io_pbuf_get_region        | kbuf.c                           | function parameter                
io_provide_buffers      | kbuf.c                    | req, issue_flags                                                   | io_provide_buffers        | kbuf.c                           | function parameter                
io_provide_buffers_prep | kbuf.c                    | req, sqe                                                          | io_provide_buffers_prep   | kbuf.c                           | function parameter                
io_provided_buffer_select| kbuf.c                  | req, len                                                          | io_provided_buffer_select | kbuf.c                           | function parameter                
io_provided_buffers_select| kbuf.c                 | req, len                                                          | io_provided_buffers_select| kbuf.c                           | function parameter                
io_put_bl               | kbuf.c                    | ctx, bl                                                           | io_put_bl                 | kbuf.c                           | function parameter                
__io_put_kbuf           | kbuf.c                    | req, len, issue_flags                                              | __io_put_kbuf             | kbuf.c                           | function parameter                
__io_put_kbuf_list      | kbuf.c                    | req, len, io_buffers_comp                                          | __io_put_kbuf_list        | kbuf.c                           | function parameter                
io_refill_buffer_cache  | kbuf.c                    | ctx                                                               | io_refill_buffer_cache    | kbuf.c                           | function parameter                
io_register_pbuf_ring   | kbuf.c                    | ctx, arg                                                           | io_register_pbuf_ring     | kbuf.c                           | function parameter                
io_register_pbuf_status  | kbuf.c                    | ctx, arg                                                           | io_register_pbuf_status   | kbuf.c                           | function parameter                
__io_remove_buffers     | kbuf.c                    | ctx                                                               | __io_remove_buffers       | kbuf.c                           | function parameter                
io_remove_buffers       | kbuf.c                    | req, issue_flags                                                   | io_remove_buffers         | kbuf.c                           | function parameter                
io_remove_buffers_prep  | kbuf.c                    | req, sqe                                                          | io_remove_buffers_prep    | kbuf.c                           | function parameter                
io_ring_buffer_select  | kbuf.c                    | req, len                                                          | io_ring_buffer_select     | kbuf.c                           | function parameter                
io_ring_buffers_peek   | kbuf.c                    | req, arg                                                          | io_ring_buffers_peek      | kbuf.c                           | function parameter                
io_ring_head_to_buf    | kbuf.c                    | br, head, mask                                                    | io_ring_head_to_buf       | kbuf.c                           | function parameter                
io_unregister_pbuf_ring | kbuf.c                   | ctx, arg                                                           | io_unregister_pbuf_ring   | kbuf.c                           | function parameter                
is_power_of_2           | kbuf.c                    | reg                                                               | is_power_of_2             | kbuf.c                           | function parameter                
scoped_guard            | kbuf.c                    | mutex, ctx->mmap_lock                                             | scoped_guard              | kbuf.c                           | function parameter                
xa_erase                | kbuf.c                    | ctx->io_bl_xa, bl->bgid                                            | xa_erase                  | kbuf.c                           | function parameter                
xa_err                  | kbuf.c                    | xa_store, ctx->io_bl_xa                                            | xa_err                    | kbuf.c                           | function parameter                
xa_find                 | kbuf.c                    | ctx->io_bl_xa, index, ULONG_MAX                                    | xa_find                   | kbuf.c                           | function parameter                
xa_store                | kbuf.c                    | ctx->io_bl_xa, bgid, bl                                           | xa_store                  | kbuf.c                           | function parameter        
access_ok               | kbuf.c               | u64_to_user_ptr(p->addr), size                                   | access_ok               | kbuf.c               | function call
io_buffer_select       | kbuf.c                     | req, len                                                         | io_buffer_select        | kbuf.c                          | function definition
io_buffers_peek        | kbuf.c                     | req, arg                                                         | io_buffers_peek         | kbuf.c                          | function definition
io_buffers_select      | kbuf.c                     | req, arg                                                         | io_buffers_select       | kbuf.c                          | function definition                     
min_not_zero              | kbuf.c       | needed, PEEK_MAX_IMPORT                              | min_not_zero              | kbuf.c            | macro
min_t                     | kbuf.c       | tail - head, UIO_MAXIOV                              | min_t                     | kbuf.c            | macro
list_add               | kbuf.c                    | list_add(&buf->list, &bl->buf_list)                                        | list_add                | kbuf.c                         | function call
list_entry             | kbuf.c                    | buf = list_entry(item, struct io_buffer, list)                             | list_entry              | kbuf.c                         | function call
list_move_tail         | kbuf.c                    | list_move_tail(&buf->list, &bl->buf_list)                                  | list_move_tail          | kbuf.c                         | function call
access_ok              | kbuf.c                       | access_ok(u64_to_user_ptr(...), size)              | access_ok               | kbuf.c                         | function call
io_buffer_select       | kbuf.c                       | io_buffer_select(req, len)                          | io_buffer_select        | kbuf.c                         | function call
io_uring_fill_params|io_uring/io_uring.h|unsigned entries, struct io_uring_params *p|io_uring_fill_params|io_uring/io_uring.h|fills user-provided io_uring_params during setup
io_cqe_cache_refill|io_uring/io_uring.h|struct io_ring_ctx *ctx, bool overflow|io_cqe_cache_refill|io_uring/io_uring.h|refills completion queue entry cache
io_run_task_work_sig|io_uring/io_uring.h|struct io_ring_ctx *ctx|io_run_task_work_sig|io_uring/io_uring.h|runs deferred task work with signal
io_req_defer_failed|io_uring/io_uring.h|struct io_kiocb *req, s32 res|io_req_defer_failed|io_uring/io_uring.h|handles request failure after deferral
io_post_aux_cqe|io_uring/io_uring.h|struct io_ring_ctx *ctx, u64 user_data, s32 res, u32 cflags|io_post_aux_cqe|io_uring/io_uring.h|posts an auxiliary completion queue entry
io_add_aux_cqe|io_uring/io_uring.h|struct io_ring_ctx *ctx, u64 user_data, s32 res, u32 cflags|io_add_aux_cqe|io_uring/io_uring.h|adds auxiliary CQE to ring
io_req_post_cqe|io_uring/io_uring.h|struct io_kiocb *req, s32 res, u32 cflags|io_req_post_cqe|io_uring/io_uring.h|posts completion result for request
__io_commit_cqring_flush|io_uring/io_uring.h|struct io_ring_ctx *ctx|__io_commit_cqring_flush|io_uring/io_uring.h|flushes the CQ ring to user
io_file_get_normal|io_uring/io_uring.h|struct io_kiocb *req, int fd|io_file_get_normal|io_uring/io_uring.h|gets normal (non-fixed) file from fd
io_file_get_fixed|io_uring/io_uring.h|struct io_kiocb *req, int fd, struct file **f|io_file_get_fixed|io_uring/io_uring.h|retrieves file from fixed index
__io_req_task_work_add|io_uring/io_uring.h|struct io_kiocb *req, unsigned flags|__io_req_task_work_add|io_uring/io_uring.h|adds task work to the task queue
io_req_task_work_add_remote|io_uring/io_uring.h|struct io_kiocb *req, struct io_ring_ctx *ctx, unsigned flags|io_req_task_work_add_remote|io_uring/io_uring.h|adds task work to remote task
io_alloc_async_data|io_uring/io_uring.h|struct io_kiocb *req|io_alloc_async_data|io_uring/io_uring.h|allocates async data for request
io_req_task_queue|io_uring/io_uring.h|struct io_kiocb *req|io_req_task_queue|io_uring/io_uring.h|queues task work for request
io_req_task_complete|io_uring/io_uring.h|struct io_kiocb *req, struct io_tw_state *ts|io_req_task_complete|io_uring/io_uring.h|completes task request
io_req_task_queue_fail|io_uring/io_uring.h|struct io_kiocb *req, int ret|io_req_task_queue_fail|io_uring/io_uring.h|queues a failed task request
io_req_task_submit|io_uring/io_uring.h|struct io_kiocb *req, struct io_tw_state *ts|io_req_task_submit|io_uring/io_uring.h|submits a task request
io_handle_tw_list|io_uring/io_uring.h|struct llist_node *node, unsigned int *count, unsigned int max_entries|io_handle_tw_list|io_uring/io_uring.h|handles task work list
tctx_task_work_run|io_uring/io_uring.h|struct io_uring_task *tctx, unsigned int max_entries, unsigned int *count|tctx_task_work_run|io_uring/io_uring.h|runs task work for a given task context
tctx_task_work|io_uring/io_uring.h|struct callback_head *cb|tctx_task_work|io_uring/io_uring.h|entry point for task work processing
io_uring_cancel_generic|io_uring/io_uring.h|bool cancel_all, struct io_sq_data *sqd|io_uring_cancel_generic|io_uring/io_uring.h|cancels all requests if needed
io_uring_alloc_task_context|io_uring/io_uring.h|struct task_struct *task, struct io_ring_ctx *ctx|io_uring_alloc_task_context|io_uring/io_uring.h|allocates io_uring context for a task
io_ring_add_registered_file|io_uring/io_uring.h|struct io_uring_task *tctx, struct file *file, u32 index|io_ring_add_registered_file|io_uring/io_uring.h|adds file to registered list
io_req_queue_iowq|io_uring/io_uring.h|struct io_kiocb *req|io_req_queue_iowq|io_uring/io_uring.h|queues request to io worker queue
io_poll_issue|io_uring/io_uring.h|struct io_kiocb *req, struct io_tw_state *ts|io_poll_issue|io_uring/io_uring.h|issues a poll-type request
io_submit_sqes|io_uring/io_uring.h|struct io_ring_ctx *ctx, unsigned int nr|io_submit_sqes|io_uring/io_uring.h|submits a batch of SQEs
io_do_iopoll|io_uring/io_uring.h|struct io_ring_ctx *ctx, bool force_nonspin|io_do_iopoll|io_uring/io_uring.h|performs I/O polling
__io_submit_flush_completions|io_uring/io_uring.h|struct io_ring_ctx *ctx|__io_submit_flush_completions|io_uring/io_uring.h|flushes completion ring entries
io_wq_free_work|io_uring/io_uring.h|struct io_wq_work *work|io_wq_free_work|io_uring/io_uring.h|frees an io_wq_work structure
io_wq_submit_work|io_uring/io_uring.h|struct io_wq_work *work|io_wq_submit_work|io_uring/io_uring.h|submits io_wq work
io_free_req|io_uring/io_uring.h|struct io_kiocb *req|io_free_req|io_uring/io_uring.h|frees a request
io_queue_next|io_uring/io_uring.h|struct io_kiocb *req|io_queue_next|io_uring/io_uring.h|queues the next request in chain
io_task_refs_refill|io_uring/io_uring.h|struct io_uring_task *tctx|io_task_refs_refill|io_uring/io_uring.h|refills task ref counters
__io_alloc_req_refill|io_uring/io_uring.h|struct io_ring_ctx *ctx|__io_alloc_req_refill|io_uring/io_uring.h|refills internal request pool
io_match_task_safe|io_uring/io_uring.h|struct io_kiocb *head, struct io_uring_task *tctx, bool cancel_all|io_match_task_safe|io_uring/io_uring.h|matches tasks safely for cancellation
io_activate_pollwq|io_uring/io_uring.h|struct io_ring_ctx *ctx|io_activate_pollwq|io_uring/io_uring.h|activates polling worker queue
o_renameat_prep | io_uring/fs.h | struct io_kiocb*, struct io_uring_sqe* | io_renameat_prep | io_uring/fs.h | function parameter
io_renameat    | io_uring/fs.h | struct io_kiocb*, unsigned int | io_renameat | io_uring/fs.h | function parameter
io_renameat_cleanup | io_uring/fs.h | struct io_kiocb* | io_renameat_cleanup | io_uring/fs.h | function parameter
io_unlinkat_prep | io_uring/fs.h | struct io_kiocb*, struct io_uring_sqe* | io_unlinkat_prep | io_uring/fs.h | function parameter
io_unlinkat    | io_uring/fs.h | struct io_kiocb*, unsigned int | io_unlinkat | io_uring/fs.h | function parameter
io_unlinkat_cleanup | io_uring/fs.h | struct io_kiocb* | io_unlinkat_cleanup | io_uring/fs.h | function parameter
io_mkdirat_prep | io_uring/fs.h | struct io_kiocb*, struct io_uring_sqe* | io_mkdirat_prep | io_uring/fs.h | function parameter
io_mkdirat     | io_uring/fs.h | struct io_kiocb*, unsigned int | io_mkdirat | io_uring/fs.h | function parameter
io_mkdirat_cleanup | io_uring/fs.h | struct io_kiocb* | io_mkdirat_cleanup | io_uring/fs.h | function parameter
io_symlinkat_prep | io_uring/fs.h | struct io_kiocb*, struct io_uring_sqe* | io_symlinkat_prep | io_uring/fs.h | function parameter
io_symlinkat   | io_uring/fs.h | struct io_kiocb*, unsigned int | io_symlinkat | io_uring/fs.h | function parameter
io_linkat_prep | io_uring/fs.h | struct io_kiocb*, struct io_uring_sqe* | io_linkat_prep | io_uring/fs.h | function parameter
io_linkat      | io_uring/fs.h | struct io_kiocb*, unsigned int | io_linkat | io_uring/fs.h | function parameter
io_link_cleanup | io_uring/fs.h | struct io_kiocb* | io_link_cleanup | io_uring/fs.h | function parameter
io_wq          | io_uring/io-wq.h | - | io_wq | io_uring/io-wq.h | structure for I/O work queue
io_wq_work_fn  | io_uring/io-wq.h | typedef for function pointer | io_wq_work_fn | io_uring/io-wq.h | function pointer type for work function
free_work_fn   | io_uring/io-wq.h | typedef for function pointer | free_work_fn | io_uring/io-wq.h | function pointer type for freeing work
io_wq_hash     | io_uring/io-wq.h | struct wait_queue_head wait | io_wq_hash | io_uring/io-wq.h | structure for managing I/O work queue hash
io_wq_data     | io_uring/io-wq.h | struct io_wq_hash* hash, struct task_struct* task | io_wq_data | io_uring/io-wq.h | structure for managing I/O work queue data
io_wq_create   | io_uring/io-wq.h | unsigned bounded, struct io_wq_data* data | io_wq_create | io_uring/io-wq.h | function for creating an I/O work queue
io_wq_exit_start | io_uring/io-wq.h | struct io_wq* | io_wq_exit_start | io_uring/io-wq.h | function to start I/O work queue exit
io_wq_put_and_exit | io_uring/io-wq.h | struct io_wq* | io_wq_put_and_exit | io_uring/io-wq.h | function to put and exit I/O work queue
io_wq_enqueue  | io_uring/io-wq.h | struct io_wq* wq, struct io_wq_work* work | io_wq_enqueue | io_uring/io-wq.h | function for enqueueing work in I/O work queue
io_wq_hash_work | io_uring/io-wq.h | struct io_wq_work* work, void* val | io_wq_hash_work | io_uring/io-wq.h | function for hashing work in I/O work queue
io_wq_cpu_affinity | io_uring/io-wq.h | struct io_uring_task* tctx, cpumask_var_t mask | io_wq_cpu_affinity | io_uring/io-wq.h | function for setting CPU affinity for I/O work queue
io_wq_max_workers | io_uring/io-wq.h | struct io_wq* wq, int* new_count | io_wq_max_workers | io_uring/io-wq.h | function for setting maximum number of workers in I/O work queue
io_wq_is_hashed | io_uring/io-wq.h | struct io_wq_work* work | io_wq_is_hashed | io_uring/io-wq.h | function to check if work is hashed in I/O work queue
work_cancel_fn | io_uring/io-wq.h | typedef for function pointer | work_cancel_fn | io_uring/io-wq.h | function pointer type for canceling work
io_wq_cancel_cb | io_uring/io-wq.h | struct io_wq* wq, work_cancel_fn* cancel | io_wq_cancel_cb | io_uring/io-wq.h | function for canceling work in I/O work queue
io_wq_worker_sleeping | io_uring/io-wq.h | struct task_struct* tsk | io_wq_worker_sleeping | io_uring/io-wq.h | function for worker sleeping state
io_wq_worker_running | io_uring/io-wq.h | struct task_struct* tsk | io_wq_worker_running | io_uring/io-wq.h | function for worker running state
io_futex_prep | io_uring/futex.h | struct io_kiocb*, struct io_uring_sqe* | io_futex_prep | io_uring/futex.h | function to prepare futex operation
io_futexv_prep | io_uring/futex.h | struct io_kiocb*, struct io_uring_sqe* | io_futexv_prep | io_uring/futex.h | function to prepare futexv operation
io_futex_wait | io_uring/futex.h | struct io_kiocb*, unsigned int | io_futex_wait | io_uring/futex.h | function to perform futex wait operation
io_futexv_wait | io_uring/futex.h | struct io_kiocb*, unsigned int | io_futexv_wait | io_uring/futex.h | function to perform futexv wait operation
io_futex_wake | io_uring/futex.h | struct io_kiocb*, unsigned int | io_futex_wake | io_uring/futex.h | function to perform futex wake operation
io_futex_cancel | io_uring/futex.h | struct io_ring_ctx* ctx, struct io_cancel_data* cd | io_futex_cancel | io_uring/futex.h | function to cancel futex operation
io_futex_remove_all | io_uring/futex.h | struct io_ring_ctx* ctx, struct io_uring_task* tctx, bool cancel_all | io_futex_remove_all | io_uring/futex.h | function to remove all futex operations
io_futex_cache_init | io_uring/futex.h | struct io_ring_ctx* ctx | io_futex_cache_init | io_uring/futex.h | function to initialize futex cache
io_futex_cache_free | io_uring/futex.h | struct io_ring_ctx* ctx | io_futex_cache_free | io_uring/futex.h | function to free futex cache
io_buffer_list | io_uring/kbuf.h | struct list_head buf_list, struct io_uring_buf_ring* buf_ring | io_buffer_list | io_uring/kbuf.h | structure for managing a list of buffers
io_buffer | io_uring/kbuf.h | struct list_head list | io_buffer | io_uring/kbuf.h | structure for managing individual buffer
buf_sel_arg | io_uring/kbuf.h | struct iovec* iovs | buf_sel_arg | io_uring/kbuf.h | argument for buffer selection
io_buffer_select | io_uring/kbuf.h | struct io_kiocb* req, size_t* len | io_buffer_select | io_uring/kbuf.h | function to select buffer
io_buffers_select | io_uring/kbuf.h | struct io_kiocb* req, struct buf_sel_arg* arg | io_buffers_select | io_uring/kbuf.h | function to select buffers
io_buffers_peek | io_uring/kbuf.h | struct io_kiocb* req, struct buf_sel_arg* arg | io_buffers_peek | io_uring/kbuf.h | function to peek buffers
io_destroy_buffers | io_uring/kbuf.h | struct io_ring_ctx* ctx | io_destroy_buffers | io_uring/kbuf.h | function to destroy buffers
io_remove_buffers_prep | io_uring/kbuf.h | struct io_kiocb* req, struct io_uring_sqe* sqe | io_remove_buffers_prep | io_uring/kbuf.h | function to prepare removal of buffers
io_remove_buffers | io_uring/kbuf.h | struct io_kiocb* req, unsigned int issue_flags | io_remove_buffers | io_uring/kbuf.h | function to remove buffers
io_provide_buffers_prep | io_uring/kbuf.h | struct io_kiocb* req, struct io_uring_sqe* sqe | io_provide_buffers_prep | io_uring/kbuf.h | function to prepare buffer provision
io_provide_buffers | io_uring/kbuf.h | struct io_kiocb* req, unsigned int issue_flags | io_provide_buffers | io_uring/kbuf.h | function to provide buffers
io_register_pbuf_ring | io_uring/kbuf.h | struct io_ring_ctx* ctx, void __user* arg | io_register_pbuf_ring | io_uring/kbuf.h | function to register buffer ring
io_unregister_pbuf_ring | io_uring/kbuf.h | struct io_ring_ctx* ctx, void __user* arg | io_unregister_pbuf_ring | io_uring/kbuf.h | function to unregister buffer ring
io_register_pbuf_status | io_uring/kbuf.h | struct io_ring_ctx* ctx, void __user* arg | io_register_pbuf_status | io_uring/kbuf.h | function to register buffer status
__io_put_kbuf | io_uring/kbuf.h | struct io_kiocb* req, int len, unsigned issue_flags | __io_put_kbuf | io_uring/kbuf.h | function to put kernel buffer
io_kbuf_recycle_legacy | io_uring/kbuf.h | struct io_kiocb* req, unsigned issue_flags | io_kbuf_recycle_legacy | io_uring/kbuf.h | function to recycle legacy kernel buffer
io_pbuf_get_region | io_uring/kbuf.h | struct io_ring_ctx* ctx | io_pbuf_get_region | io_uring/kbuf.h | function to get mapped region of pbuf
io_kbuf_recycle_ring | io_uring/kbuf.h | struct io_kiocb* req | io_kbuf_recycle_ring | io_uring/kbuf.h | function to recycle buffer ring
io_do_buffer_select | io_uring/kbuf.h | struct io_kiocb* req | io_do_buffer_select | io_uring/kbuf.h | function to select buffer in legacy buffer
io_kbuf_recycle | io_uring/kbuf.h | struct io_kiocb* req, unsigned issue_flags | io_kbuf_recycle | io_uring/kbuf.h | function to recycle kernel buffer
io_kbuf_commit | io_uring/kbuf.h | struct io_kiocb* req, struct io_buffer_list* bl, int len, int nr | io_kbuf_commit | io_uring/kbuf.h | function to commit kernel buffer
__io_put_kbuf_ring | io_uring/kbuf.h | struct io_kiocb* req, int len, int nr | __io_put_kbuf_ring | io_uring/kbuf.h | function to put kbuf ring
__io_put_kbuf_list | io_uring/kbuf.h | struct io_kiocb* req, int len, struct list_head* list | __io_put_kbuf_list | io_uring/kbuf.h | function to put kbuf list
io_kbuf_drop | io_uring/kbuf.h | struct io_kiocb* req | io_kbuf_drop | io_uring/kbuf.h | function to drop kernel buffer
__io_put_kbufs | io_uring/kbuf.h | struct io_kiocb* req, int len | __io_put_kbufs | io_uring/kbuf.h | function to put kbufs
io_put_kbuf | io_uring/kbuf.h | struct io_kiocb* req, int len | io_put_kbuf | io_uring/kbuf.h | function to put kernel buffer
io_put_kbufs | io_uring/kbuf.h | struct io_kiocb* req, int len | io_put_kbufs | io_uring/kbuf.h | function to put multiple kernel buffers
io_alloc_file_tables | io_uring/filetable.h | struct io_ring_ctx* ctx, struct io_file_table* table, unsigned nr_files | io_alloc_file_tables | io_uring/filetable.h | function to allocate file tables
io_free_file_tables | io_uring/filetable.h | struct io_ring_ctx* ctx, struct io_file_table* table | io_free_file_tables | io_uring/filetable.h | function to free file tables
io_fixed_fd_install | io_uring/filetable.h | struct io_kiocb* req, unsigned int issue_flags, struct file* file, unsigned int file_slot | io_fixed_fd_install | io_uring/filetable.h | function to install a fixed fd
__io_fixed_fd_install | io_uring/filetable.h | struct io_ring_ctx* ctx, struct file* file | __io_fixed_fd_install | io_uring/filetable.h | function to install fixed fd (internal)
io_fixed_fd_remove | io_uring/filetable.h | struct io_ring_ctx* ctx, unsigned int offset | io_fixed_fd_remove | io_uring/filetable.h | function to remove fixed fd
io_register_file_alloc_range | io_uring/filetable.h | struct io_ring_ctx* ctx, struct io_uring_file_index_range __user* arg | io_register_file_alloc_range | io_uring/filetable.h | function to register file allocation range
io_file_get_flags | io_uring/filetable.h | struct file* file | io_file_get_flags | io_uring/filetable.h | function to get file flags
io_file_bitmap_clear | io_uring/filetable.h | struct io_file_table* table, int bit | io_file_bitmap_clear | io_uring/filetable.h | function to clear file bitmap
io_file_bitmap_set | io_uring/filetable.h | struct io_file_table* table, int bit | io_file_bitmap_set | io_uring/filetable.h | function to set file bitmap
io_slot_flags | io_uring/filetable.h | struct io_rsrc_node* node | io_slot_flags | io_uring/filetable.h | function to get flags for file slot
io_slot_file | io_uring/filetable.h | struct io_rsrc_node* node | io_slot_file | io_uring/filetable.h | function to get file associated with a slot
io_fixed_file_set | io_uring/filetable.h | struct io_rsrc_node* node, struct file* file | io_fixed_file_set | io_uring/filetable.h | function to set file for fixed slot
io_file_table_set_alloc_range | io_uring/filetable.h | struct io_ring_ctx* ctx | io_file_table_set_alloc_range | io_uring/filetable.h | function to set allocation range for file table
io_alloc_file_tables | io_uring/filetable.h | struct io_ring_ctx* ctx, struct io_file_table* table, unsigned nr_files | io_alloc_file_tables | io_uring/filetable.h | function to allocate file tables
io_free_file_tables | io_uring/filetable.h | struct io_ring_ctx* ctx, struct io_file_table* table | io_free_file_tables | io_uring/filetable.h | function to free file tables
io_fixed_fd_install | io_uring/filetable.h | struct io_kiocb* req, unsigned int issue_flags, struct file* file, unsigned int file_slot | io_fixed_fd_install | io_uring/filetable.h | function to install a fixed fd
__io_fixed_fd_install | io_uring/filetable.h | struct io_ring_ctx* ctx, struct file* file | __io_fixed_fd_install | io_uring/filetable.h | function to install fixed fd (internal)
io_fixed_fd_remove | io_uring/filetable.h | struct io_ring_ctx* ctx, unsigned int offset | io_fixed_fd_remove | io_uring/filetable.h | function to remove fixed fd
io_register_file_alloc_range | io_uring/filetable.h | struct io_ring_ctx* ctx, struct io_uring_file_index_range __user* arg | io_register_file_alloc_range | io_uring/filetable.h | function to register file allocation range
io_file_get_flags | io_uring/filetable.h | struct file* file | io_file_get_flags | io_uring/filetable.h | function to get file flags
io_file_bitmap_clear | io_uring/filetable.h | struct io_file_table* table, int bit | io_file_bitmap_clear | io_uring/filetable.h | function to clear file bitmap
io_file_bitmap_set | io_uring/filetable.h | struct io_file_table* table, int bit | io_file_bitmap_set | io_uring/filetable.h | function to set file bitmap
io_slot_flags | io_uring/filetable.h | struct io_rsrc_node* node | io_slot_flags | io_uring/filetable.h | function to get flags for file slot
io_slot_file | io_uring/filetable.h | struct io_rsrc_node* node | io_slot_file | io_uring/filetable.h | function to get file associated with a slot
io_fixed_file_set | io_uring/filetable.h | struct io_rsrc_node* node, struct file* file | io_fixed_file_set | io_uring/filetable.h | function to set file for fixed slot
io_file_table_set_alloc_range | io_uring/filetable.h | struct io_ring_ctx* ctx | io_file_table_set_alloc_range | io_uring/filetable.h | function to set allocation range for file table
