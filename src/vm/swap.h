#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "threads/thread.h"


struct swap_entry {
    struct list_elem elem;
    tid_t tid;
    struct frame_entry *fe;
     
};

struct list swap_table;

#endif