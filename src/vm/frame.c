#include "vm/frame.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static int fid_max;

void frame_init (void)
{
    lock_init (&frame_lock);
    list_init (&frame_table);
    printf("frame lock addr : %p\n", &frame_lock);
    fid_max = 0;
}

struct frame_entry* frame_get_page (enum palloc_flags flags) 
{
    ASSERT (flags & PAL_USER);
    void* kpage;
    kpage = palloc_get_page(flags);
    //printf("frame_get_page k : %p, flag : %d\n", kpage, flags);
    if (kpage) {
        lock_acquire(&frame_lock);
        struct frame_entry *fe;
        fe = malloc (sizeof(struct frame_entry));
        ASSERT (fe);
        fe->fid = fid_max++;
        fe->tid = thread_current()->tid;
        fe->kpage = kpage;
        fe->LRU = 0;
        fe->flags = flags;
        struct list_elem* e;
        // set LRU
        for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)) {
            list_entry(e, struct frame_entry, elem)->LRU++;
        }
        //lock_init(&fe->fe_lock);
        list_push_back (&frame_table, &fe->elem);
        lock_release(&frame_lock);
        return fe;
    } else {
        struct list_elem *e;
        struct frame_entry* fe;
        struct frame_entry* fe_evict;
        fe_evict = NULL;
        //lock_acquire(&evict_lock);
        lock_acquire(&frame_lock);
        for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)) {
            fe = list_entry(e, struct frame_entry, elem);
            //printf("\tfe->k : %p, flag : %d, LRU : %d\n", fe->kpage, fe->flags, fe->LRU);
            if (fe_evict == NULL) {
                if ((fe->flags & PAL_ZERO) == false) {
                    //printf("\t\tpick k : %p, flag : %d, LRU : %d\n", fe->kpage, fe->flags, fe->LRU);
                    fe_evict = fe;
                }
            } else if (fe->LRU > fe_evict->LRU) {
                //printf("\t\tfe_evict->LRU : %d\n",fe_evict->LRU);
                //printf("\t\tpicks k : %p, flag : %d, LRU : %d\n", fe->kpage, fe->flags, fe->LRU);
                fe_evict = fe;
            }
        }
        //lock_acquire(&fe_evict->fe_lock);
        lock_release(&frame_lock);
        
        //printf("fe_evict : %p\n", fe_evict);

        swap_out(&thread_current()->spt, fe_evict);
        lock_acquire(&frame_lock);
        kpage = palloc_get_page(flags);
        //printf("\tcall palloc_get_page %p\n", kpage);
        fe = malloc (sizeof(struct frame_entry));
        ASSERT (fe);
        fe->fid = fid_max++;
        fe->tid = thread_current()->tid;
        fe->kpage = kpage;
        fe->LRU = 0;
        fe->flags = flags;
        // set LRU
        for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)) {
            list_entry(e, struct frame_entry, elem)->LRU++;
        }
        list_push_back (&frame_table, &fe->elem);
        lock_release(&frame_lock);
        //lock_release(&evict_lock);
        return fe;
    }
}

void frame_free_page (void *kpage)
{
    ASSERT (is_kernel_vaddr(kpage));
    printf("frame free page %p\n", kpage);
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