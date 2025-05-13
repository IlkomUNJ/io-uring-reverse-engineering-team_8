#ifndef INTERNAL_IO_SLIST_H
#define INTERNAL_IO_SLIST_H

#include <linux/io_uring_types.h>

/* Macro: __wq_list_for_each
 * Iterates over each work node in the work list starting from 'head'.
 */
#define __wq_list_for_each(pos, head)               \
    for (pos = (head)->first; pos; pos = (pos)->next)

/* Macro: wq_list_for_each
 * Iterates over each work node in the list while also keeping track of the previous node.
 */
#define wq_list_for_each(pos, prv, head)            \
    for (pos = (head)->first, prv = NULL; pos; prv = pos, pos = (pos)->next)

/* Macro: wq_list_for_each_resume
 * Resumes iteration over the work list from the current position, updating the previous node.
 */
#define wq_list_for_each_resume(pos, prv)           \
    for (; pos; prv = pos, pos = (pos)->next)

/* Macro: wq_list_empty
 * Checks whether the work list is empty.
 */
#define wq_list_empty(list) (READ_ONCE((list)->first) == NULL)

/* Macro: INIT_WQ_LIST
 * Initializes the work list by setting the first node to NULL.
 */
#define INIT_WQ_LIST(list)  do {                \
    (list)->first = NULL;                   \
} while (0)

/*
 * Function: wq_list_add_after
 * Purpose : Inserts a work node 'node' immediately after the node 'pos' in the work list.
 *           If 'pos' was the last node, updates the list's last pointer to the new node.
 */
static inline void wq_list_add_after(struct io_wq_work_node *node,
                     struct io_wq_work_node *pos,
                     struct io_wq_work_list *list)
{
    struct io_wq_work_node *next = pos->next;

    pos->next = node;
    node->next = next;
    if (!next)
        list->last = node;
}

/*
 * Function: wq_list_add_tail
 * Purpose : Adds a work node 'node' to the tail of the work list.
 *           If the list is empty, sets both the first and last pointers to 'node'.
 */
static inline void wq_list_add_tail(struct io_wq_work_node *node,
                    struct io_wq_work_list *list)
{
    node->next = NULL;
    if (!list->first) {
        list->last = node;
        WRITE_ONCE(list->first, node);
    } else {
        list->last->next = node;
        list->last = node;
    }
}

/*
 * Function: wq_list_add_head
 * Purpose : Inserts a work node 'node' at the head of the work list.
 *           Updates the list's last pointer if the list was previously empty.
 */
static inline void wq_list_add_head(struct io_wq_work_node *node,
                    struct io_wq_work_list *list)
{
    node->next = list->first;
    if (!node->next)
        list->last = node;
    WRITE_ONCE(list->first, node);
}

/*
 * Function: wq_list_cut
 * Purpose : Removes a segment from the work list starting at 'node' up to 'last'.
 *           Adjusts pointers accordingly so that the sub-list is detached.
 */
static inline void wq_list_cut(struct io_wq_work_list *list,
                   struct io_wq_work_node *last,
                   struct io_wq_work_node *prev)
{
    /* If 'node' is the first in the list (prev == NULL) */
    if (!prev)
        WRITE_ONCE(list->first, last->next);
    else
        prev->next = last->next;

    if (last == list->last)
        list->last = prev;
    last->next = NULL;
}

/*
 * Function: __wq_list_splice
 * Purpose : Splices a work list into another by attaching the entire list
 *           before the node 'to'. After splicing, the source list is reinitialized.
 */
static inline void __wq_list_splice(struct io_wq_work_list *list,
                    struct io_wq_work_node *to)
{
    list->last->next = to->next;
    to->next = list->first;
    INIT_WQ_LIST(list);
}

/*
 * Function: wq_list_splice
 * Purpose : Splices the source work list into another list if the source list is non-empty.
 *           Returns true if splicing occurred.
 */
static inline bool wq_list_splice(struct io_wq_work_list *list,
                  struct io_wq_work_node *to)
{
    if (!wq_list_empty(list)) {
        __wq_list_splice(list, to);
        return true;
    }
    return false;
}

/*
 * Function: wq_stack_add_head
 * Purpose : Pushes a work node 'node' onto the head of a stack represented as a linked list.
 */
static inline void wq_stack_add_head(struct io_wq_work_node *node,
                     struct io_wq_work_node *stack)
{
    node->next = stack->next;
    stack->next = node;
}

/*
 * Function: wq_list_del
 * Purpose : Deletes a work node 'node' from the work list by invoking wq_list_cut.
 */
static inline void wq_list_del(struct io_wq_work_list *list,
                   struct io_wq_work_node *node,
                   struct io_wq_work_node *prev)
{
    wq_list_cut(list, node, prev);
}

/*
 * Function: wq_stack_extract
 * Purpose : Pops and returns the top work node from the stack.
 *           Adjusts the stack pointer to the next node.
 */
static inline struct io_wq_work_node *wq_stack_extract(struct io_wq_work_node *stack)
{
    struct io_wq_work_node *node = stack->next;

    stack->next = node->next;
    return node;
}

/*
 * Function: wq_next_work
 * Purpose : Retrieves the next work element from the given work structure.
 *           Returns NULL if there is no next work item.
 */
static inline struct io_wq_work *wq_next_work(struct io_wq_work *work)
{
    if (!work->list.next)
        return NULL;

    return container_of(work->list.next, struct io_wq_work, list);
}

#endif // INTERNAL_IO_SLIST_H
