#include <frame.h>
#include "threads/palloc.h"
#include "threads/malloc.h"

static int fid_max;

void frame_init (void)
{
    lock_init (&frame_lock);
    list_init (&frame_table);
    fid_max = 0;
}

void* frame_get_page (enum palloc_flags flags) 
{
    ASSERT (flags & PAL_USER);
    void* kpage;
    kpage = palloc_get_page(flags);
    if (kpage) {
        struct frame_entry *fe;
        fe = malloc (sizeof(struct frame_entry));
        ASSERT (fe);
        fe->fid = fid_max++;
        fe->tid = thread_current()->tid;
        fe->kpage = kpage;
        fe->LRU = 0;
        list_push_back (&frame_table, fe);

        return kpage;
    } else {
        PANIC("eviction requirement");
    }
}

void* frame_free_page (void *kpage)
{
    ASSERT (is_kernel_vaddr(kpage));
    struct frame_entry* fe;
    fe = frame_lookup(kpage);
    ASSERT (fe);
    list_remove (&fe->elem);
    palloc_free_page(kpage);
}

struct frame_entry* frame_lookup (void *kpage)
{
    lock_acquire (&frame_lock);
    struct list_elem *e;
    for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)) {
        struct frame_entry *fe;
        fe = list_entry(e, struct frame_entry, elem);
        if (fe->kpage == kpage)
        {
            lock_release (&frame_lock);
            return fe;
        }
    }
    lock_release (&frame_lock);
    return NULL;
}