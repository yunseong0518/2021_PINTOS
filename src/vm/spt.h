#ifndef VM_SPT_H
#define VM_SPT_H

#include <stdio.h>
#include <hash.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "filesys/file.h"
#include "vm/frame.h"

struct spt_entry
{
    int fid;
    tid_t tid;
    struct thread* t;
    bool avail_swap;
    struct hash_elem elem;
    struct list_elem elem_all;
    struct frame_entry *fe;
    void* upage;
    size_t page_read_bytes;
    size_t page_zero_bytes;
    struct file *file;
    bool is_alloc;
    bool writable;
    off_t ofs;
    bool is_zero_page;
};

void spt_init (struct hash* spt, tid_t tid);
void spt_all_init ();
bool spt_add_entry (struct hash* spt, void* upage, size_t page_read_bytes, size_t page_zero_bytes, struct file *file, bool writable, off_t ofs, bool is_zero_page);
void spt_destroy (struct hash* spt);
struct spt_entry* spt_lookup (struct hash* spt, void* upage);
struct spt_entry* spt_lookup_frame (struct hash* spt, struct frame_entry* fe);
void* spt_alloc (struct hash* spt, void* upage, enum palloc_flags flags);
void spt_dealloc (struct hash* spt, void* upage);
void spt_free (struct hash* spt, void* upage);
void spt_remove_entry (struct hash* spt, void* upage);

struct lock spt_lock_all;

struct list spt_all;

#endif // VM_SPT_H