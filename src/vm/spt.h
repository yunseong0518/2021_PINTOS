#ifndef VM_SPT_H
#define VM_SPT_H

#include <stdio.h>
#include <hash.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "filesys/file.h"

struct spt_entry
{
    int fid;
    tid_t tid;
    bool avail_swap;
    struct hash_elem elem;
    void* upage;
    size_t page_read_bytes;
    size_t page_zero_bytes;
    struct file *file;
    bool writable;
    off_t ofs;
    bool is_zero_page;
};

#endif // VM_SPT_H