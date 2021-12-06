#include "vm/swap.h"
#include <bitmap.h>
#include "devices/block.h"
#include "vm/spt.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "vm/frame.h"

static struct bitmap *swap_bitmap;
static struct block *swap_device;
int swap_cnt;
#define pg_per_block (PGSIZE / BLOCK_SECTOR_SIZE)

struct lock swap_lock;

void swap_init() {
    list_init(&swap_table);
    swap_device = block_get_role(BLOCK_SWAP);
    swap_cnt = block_size(swap_device) / pg_per_block;
    ASSERT(swap_device != NULL);
    swap_bitmap = bitmap_create(swap_cnt);
    ASSERT(swap_bitmap != NULL);
    lock_init(&swap_lock);
}

void swap_in(struct hash* spt, void* kpage) {
    //printf("swap_in k : %p\n", kpage);
    lock_acquire(&swap_lock);
    if (bitmap_all(swap_bitmap, 0, swap_cnt)) {
        struct list_elem *e;
        struct frame_entry* fe;
        struct frame_entry* fe_evict;
        fe_evict = list_entry(list_begin(&frame_table), struct frame_entry, elem);
        for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)) {
            fe = list_entry(e, struct frame_entry, elem);
            if (fe->LRU > fe_evict->LRU) {
                fe_evict = fe;
            }
        }
        lock_release(&swap_lock);
        //printf("swap_out in swap_in , k : %p\n", fe_evict->kpage);
        swap_out(&thread_current()->spt, fe_evict);
        lock_acquire(&swap_lock);
    }
    int idx;
    idx = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
    struct file* file;
    int i;
    
    //void* kpage;
    //spt_add_entry(spt, upage, PGSIZE, 0, file, true, 0, false);
    //kpage = spt_alloc(spt, upage, PAL_USER);
    for (i = 0; i < pg_per_block; i++) {
        block_read(swap_device, idx * pg_per_block + i, kpage + i * BLOCK_SECTOR_SIZE);
    }
    struct swap_entry* se;
    se = malloc(sizeof(struct swap_entry));
    se->fe = frame_lookup(kpage);
    se->idx = idx;
    //printf("in frame addr : %p\n", se->fe);
    list_push_back(&swap_table, &se->elem);
    lock_release(&swap_lock);
}

void swap_out(struct hash* spt, struct frame_entry* fe) {
    printf("swap_out k : %p\n", fe->kpage);
    printf("out frame addr : %p\n", fe);

    struct list_elem* e;
    struct swap_entry* se;
    bool find_se;
    lock_acquire(&swap_lock);
    find_se = false;
    for (e = list_begin(&swap_table); e != list_end(&swap_table); e = list_next(e)) {
        se = list_entry(e, struct swap_entry, elem);
        if (se->fe == fe) {
            find_se = true;
            break;
        }
    }
    ASSERT(find_se == true);
    bitmap_reset(&swap_bitmap, se->idx);
    int i;
    for (i = 0; i < pg_per_block; i++) {
        block_write(swap_device, se->idx * pg_per_block + i, se->fe->kpage + i * BLOCK_SECTOR_SIZE);
    }
    list_remove(&se->elem);
    lock_release(&swap_lock);
}