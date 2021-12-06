#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "threads/thread.h"
#include <hash.h>
#include "vm/frame.h"


struct swap_entry {
    struct list_elem elem;
    struct frame_entry *fe;
    int idx;
};

struct list swap_table;

void swap_init(void);
void swap_in(struct hash* spt, void* kpage);
void swap_out(struct hash* spt, struct frame_entry* fe);

#endif