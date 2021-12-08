#include "vm/spt.h"
#include <stdio.h>
#include <hash.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"

static unsigned spt_hash_func (const struct hash_elem *e, void *aux) {
    struct spt_entry *se;
    se = hash_entry (e, struct spt_entry, elem);
    return hash_int(se->upage);
}

static bool spt_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux) {
    struct spt_entry *se_a, *se_b;
    se_a = hash_entry (a, struct spt_entry, elem);
    se_b = hash_entry (b, struct spt_entry, elem);
    return se_a->upage < se_b->upage;
}

void spt_init (struct hash* spt) {
    hash_init (spt, spt_hash_func, spt_less_func, NULL);
    lock_init (&thread_current()->spt_lock);
    printf("spt lock tid : %d addr : %p\n", thread_tid(), &thread_current()->spt_lock);
}

void spt_all_init () {
    list_init (&spt_all);
    lock_init(&spt_lock_all);
    printf("spt_lock_all : %p\n", &spt_lock_all);
}

bool spt_add_entry (struct hash* spt, void* upage, size_t page_read_bytes, size_t page_zero_bytes, struct file *file, bool writable, off_t ofs, bool is_zero_page) {
    lock_acquire(&spt_lock_all);
    struct spt_entry* se;
    se = malloc (sizeof(struct spt_entry));
    ASSERT (se);
    se->tid = thread_tid();
    se->avail_swap = false;
    se->upage = upage;
    se->fe = NULL;
    se->page_read_bytes = page_read_bytes;
    se->page_zero_bytes = page_zero_bytes;
    se->file = file;
    se->is_alloc = false;
    se->writable = writable;
    se->ofs = ofs;
    se->is_zero_page = is_zero_page;
    struct hash_elem* he;
    he = hash_insert (spt, &se->elem);
    list_push_back (&spt_all, &se->elem_all);
    lock_release(&spt_lock_all);
    if (he != NULL) {
        printf("spt_add_entry he NULL\n");
        return false;
    }
    else {
        return true;
    }
}

void* spt_alloc (struct hash* spt, void* upage, enum palloc_flags flags) {
    
    lock_acquire(&spt_lock_all);
    struct spt_entry* se;
    se = spt_lookup (spt, upage);
    if (se == NULL) {
        PANIC ("spt alloc no upage");
    }
    lock_release(&spt_lock_all);
    se->fe = frame_get_page (flags);
    //printf("spt add frame k : %p\n", se->fe->kpage);
    se->is_alloc = true;
    return se->fe->kpage;
}

void spt_dealloc (struct hash* spt, void* upage) {
    struct spt_entry* se;
    se = spt_lookup (spt, upage);
    if (se == NULL) PANIC ("spt_free se == NULL");
    se->is_alloc = false;
    se->fe = NULL;
}

void spt_free (struct hash* spt, void* upage) {
    //lock_acquire(&spt_lock);
    struct spt_entry* se;
    se = spt_lookup (spt, upage);
    if (se == NULL) PANIC ("spt_free se == NULL");
    if (se->fe == NULL) PANIC ("spt_free se->fe == NULL");
    if (se->fe->kpage == NULL) PANIC ("spt_free se->fe->kpage == NULL");
    frame_free_page(se->fe->kpage);
    //lock_release(&spt_lock);
}

struct spt_entry* spt_lookup (struct hash* spt, void* upage) {
    struct spt_entry se;
    struct hash_elem *he;
    se.upage = upage;
    he = hash_find (spt, &se.elem);
    if (he == NULL)
        return NULL;
    else
        return hash_entry (he, struct spt_entry, elem);
}

struct spt_entry* spt_lookup_all_frame (struct frame_entry* fe) {
    printf("tid : %d, fe->tid : %d\n", thread_tid(), fe->tid);
    lock_acquire(&spt_lock_all);
    struct list_elem *e;
    for (e = list_begin(&spt_all); e != list_end(&spt_all); e = list_next(e)) {
        struct spt_entry* se;
        se = list_entry (e, struct spt_entry, elem_all);
        if (se->fe == fe) {
            lock_release(&spt_lock_all);
            return se;
        }
    }
    printf("not found all\n");
    lock_release(&spt_lock_all);
    return NULL;
}
struct spt_entry* spt_lookup_frame (struct hash* spt, struct frame_entry* fe) {
    struct hash_iterator hi;
    hash_first (&hi, spt);
    while (hash_next(&hi)) {
        struct spt_entry* se;
        se = hash_entry (hash_cur (&hi), struct spt_entry, elem);
        if (se->fe == fe)
            return se;
    }
    printf("not found\n");
    return NULL;
}

void spt_destroy (struct hash* spt) {
    hash_destroy (spt, NULL);
}

void spt_remove_entry (struct hash* spt, void* upage) {
    struct spt_entry* se;
    struct spt_entry* se_all;
    se = spt_lookup(spt, upage);
    //printf("spt remove k : \n");
    if (se == NULL) {
        PANIC ("spt no remove entry");
    } else {
        hash_delete (spt, &se->elem);
        list_remove (&se->elem_all);
    }
    // do it later
}