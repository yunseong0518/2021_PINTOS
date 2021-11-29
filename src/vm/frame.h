#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdio.h>
#include <list.h>
#include "threads/synch.h"

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

#endif // VM_FRAME_H