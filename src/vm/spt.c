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
}

void spt_add_entry (struct hash* spt, void* upage, size_t page_read_bytes, size_t page_zero_bytes, struct file *file, bool writable, off_t ofs, bool is_zero_page) {
    struct spt_entry* se;
    se = malloc (sizeof(struct spt_entry));
    ASSERT (se);
    se->tid = thread_tid();
    se->avail_swap = false;
    se->upage = upage;
    se->page_read_bytes = page_read_bytes;
    se->page_zero_bytes = page_zero_bytes;
    se->file = file;
    se->writable = writable;
    se->ofs = ofs;
    se->is_zero_page = is_zero_page;
    struct hash_elem* he;
    he = hash_insert (spt, &se->elem);
    ASSERT (he == NULL);
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

void spt_destroy (struct hash* spt) {
    hash_destroy (spt, NULL);
}

void spt_remove_entry (struct hash* spt, void* upage) {
    struct spt_entry* se;
    se = spt_lookup(spt, upage);
    if (se == NULL) {
        PANIC ("spt no remove entry");
    } else {
        hash_delete (spt, &se->elem);
    }
    // do it later
}