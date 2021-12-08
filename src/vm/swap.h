#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "threads/thread.h"
#include <hash.h>
#include "vm/frame.h"


struct swap_entry {
    struct list_elem elem;
    void* upage;
    int idx;
};

struct list swap_table;

void swap_init(void);
void swap_in(struct hash* spt, void* kpage, void* upage);
void swap_out(struct hash* spt, struct frame_entry* fe);
struct swap_entry* swap_find(void* upage);

struct lock swap_lock;

#endif