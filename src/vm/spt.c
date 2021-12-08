#include "vm/spt.h"
#include <stdio.h>
#include <hash.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "vm/swap.h"

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

void spt_init (struct hash* spt, tid_t tid) {
    hash_init (spt, spt_hash_func, spt_less_func, NULL);
    printf("[spt_init | %d] set\n", tid);
}

void spt_all_init () {
    list_init (&spt_all);
    lock_init(&spt_lock_all);
    printf("[spt_all_init | %d] spt_lock_all : %p\n", thread_tid(), &spt_lock_all);
}

bool spt_add_entry (struct hash* spt, void* upage, size_t page_read_bytes, size_t page_zero_bytes, struct file *file, bool writable, off_t ofs, bool is_zero_page) {
    printf("[spt_add_entry | %d] begin, u : %p\n", thread_tid(), upage);
    lock_acquire(&swap_lock);
    lock_release(&swap_lock);

    lock_acquire(&spt_lock_all);
    printf("[spt_add_entry | %d] finish wait spt_lock_all\n", thread_tid());
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
        printf("[spt_add_entry | %d] he NULL\n", thread_tid());
        return false;
    }
    else {
        printf("[spt_add_entry | %d] finish\n", thread_tid());
        return true;
    }
}

void* spt_alloc (struct hash* spt, void* upage, enum palloc_flags flags) {
    printf("\t[spt_alloc | %d] begin u : %p\n", thread_tid(), upage);
    lock_acquire(&spt_lock_all);
    struct spt_entry* se;
    se = spt_lookup (spt, upage);
    if (se == NULL) {
        PANIC ("spt alloc no upage");
    }
    lock_release(&spt_lock_all);
    printf("\t[spt_alloc | %d] call frame_get_page\n", thread_tid());
    se->fe = frame_get_page (flags);
    //printf("spt add frame k : %p\n", se->fe->kpage);
    printf("\t[spt_alloc | %d] mapping u : %p, k : %p\n",thread_tid(), upage, se->fe->kpage);
    se->is_alloc = true;
    printf("\t[spt_alloc | %d] finish\n", thread_tid());
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
    lock_acquire(&spt_lock_all);
    struct spt_entry* se;
    se = spt_lookup (spt, upage);
    if (se == NULL) PANIC ("spt_free se == NULL");
    if (se->fe == NULL) PANIC ("spt_free se->fe == NULL");
    if (se->fe->kpage == NULL) PANIC ("spt_free se->fe->kpage == NULL");
    frame_free_page(se->fe->kpage);
    lock_release(&spt_lock_all);
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
    printf("\t\t\t[spt_lookup_all_frame | %d] begin, fe->tid : %d\n", thread_tid(), fe->tid);
    lock_acquire(&spt_lock_all);
    struct list_elem *e;
    for (e = list_begin(&spt_all); e != list_end(&spt_all); e = list_next(e)) {
        struct spt_entry* se;
        se = list_entry (e, struct spt_entry, elem_all);
        if (se->fe == fe) {
            lock_release(&spt_lock_all);
            printf("\t\t\t[spt_lookup_all_frame | %d] finish\n", thread_tid());
            return se;
        }
    }
    printf("\t\t\t[spt_lookup_all_frame | %d] not found all\n", thread_tid());
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