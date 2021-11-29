#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdio.h>
#include <list.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"

struct frame_entry
{
    struct list_elem elem;
    int fid;  // frame id
    tid_t tid;
    void *kpage;
    int LRU;
};

struct list frame_table;
struct lock frame_lock;

void frame_init (void);
void* frame_get_page (enum palloc_flags flags);
void frame_free_page (void *kpage);

#endif // VM_FRAME_H