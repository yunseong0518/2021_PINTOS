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


void swap_init() {
    list_init(&swap_table);
    swap_device = block_get_role(BLOCK_SWAP);
    swap_cnt = block_size(swap_device) / pg_per_block;
    //printf("block_size : %d\n", block_size(swap_device));
    ASSERT(swap_device != NULL);
    swap_bitmap = bitmap_create(swap_cnt);
    ASSERT(swap_bitmap != NULL);
    lock_init(&swap_lock);
    printf("[swap_init | %d] swap lock addr : %p\n", thread_tid(), &swap_lock);
}

struct swap_entry* swap_find(void* upage) {
    struct list_elem *e;
    for (e = list_begin(&swap_table); e != list_end(&swap_table); e = list_next(e)) {
        struct swap_entry* se;
        se = list_entry(e, struct swap_entry, elem);
        if (se->upage == upage) {
            //printf("swap find success : %p\n", upage);
            return se;
        }
    }
    return NULL;
}

void swap_in(struct hash* spt, void* kpage, void* upage) {
    printf("\t\t[swap_in | %d] begin u : %p k : %p\n", thread_tid(), upage, kpage);
    lock_acquire(&swap_lock);
    
    struct list_elem* e;
    struct swap_entry* se;
    bool find_se;
    se = swap_find(upage);
    if (se == NULL) PANIC ("swap_in not exist upage");
    //printf("swap in idx : %d\n", se->idx);
    bitmap_reset(swap_bitmap, se->idx);
    struct file* file;
    int i;
    
    //void* kpage;
    //spt_add_entry(spt, upage, PGSIZE, 0, file, true, 0, false);
    //kpage = spt_alloc(spt, upage, PAL_USER);
    struct thread* t;
    t = thread_current();
    for (i = 0; i < pg_per_block; i++) {
        block_read(swap_device, se->idx * pg_per_block + i, kpage + i * BLOCK_SECTOR_SIZE);
        printf("\t\t[swap_in | %d] block read %d : %x\n", thread_tid(), se->idx * pg_per_block + i, *(int *)(kpage + i * BLOCK_SECTOR_SIZE));
    }
    //printf("\tblock_read idx : %d\n", se->idx * pg_per_block);
    //hex_dump(0xbffffe40 , 0xbffffe40 , PHYS_BASE - 0xbffffe40 , true );
    
    for (i = 0; i < pg_per_block; i++) {
        //printf("\t\tafter page set %d : %x\n", se->idx * pg_per_block + i, *(int *)(upage + i * BLOCK_SECTOR_SIZE));
    }
    int pt;
    int pt2;

       
    //printf("in frame addr : %p\n", se->fe);
    list_remove(&se->elem);
    lock_release(&swap_lock);
    printf("\t\t[swap_in | %d] finish\n", thread_tid());
}

void swap_out(struct hash* spt, struct frame_entry* fe) {
    printf("\t\t[swap_out | %d] begin k : %p fe : %p tid : %d\n", thread_tid(), fe->kpage, fe, thread_tid());
    printf("\t\t[swap_out | %d] try swap_lock acquire\n", thread_tid());

    lock_acquire(&swap_lock);

    struct spt_entry* spt_e;
    printf("\t\t[swap_out | %d] call spt_lookup_all_frame\n", thread_tid());
    spt_e = spt_lookup_all_frame(fe);
    //printf("\tspt find %p\n", spt_e);
    
    int idx;
    idx = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
    if (idx == BITMAP_ERROR) {
        printf("ERRRRRRRRRRRRRRRRRROR\n");
    }
    struct swap_entry* se;
    se = malloc(sizeof(struct swap_entry));
    se->upage = spt_e->upage;
    se->idx = idx;
    list_push_back(&swap_table, &se->elem);
    int i;
    printf("\t\t[swap_out | %d] start block_write\n", thread_tid());
    for (i = 0; i < pg_per_block; i++) {
        printf("\t\t\t[swap_out | %d] try block write %d : %p, %x\n", thread_tid(), idx * pg_per_block + i, (fe->kpage + i * BLOCK_SECTOR_SIZE), *(int *)(fe->kpage + i * BLOCK_SECTOR_SIZE));
        //printf("\t\t[swap_out] try block write %d : %x\n", idx * pg_per_block + i, *(int *)(se->upage + i * BLOCK_SECTOR_SIZE));
        block_write(swap_device, idx * pg_per_block + i, fe->kpage + i * BLOCK_SECTOR_SIZE);
    }
    printf("\t\t[swap_out | %d] finish block_write\n", thread_tid());
    //printf("\tblock_write idx : %d\n", idx * pg_per_block);
    pagedir_clear_page(thread_current()->pagedir, spt_e->upage);
    printf("\t\t[swap_out | %d] call spt_dealloc\n", thread_tid());
    spt_dealloc(spt, spt_e->upage);
    //printf("swap_out finish idx : %d\n", idx);
    printf("\t\t[swap_out | %d] call frame_free_page\n", thread_tid());
    frame_free_page(fe->kpage);
    printf("\t\t[swap_out | %d] finish %p\n", thread_tid(), fe->kpage);
    lock_release(&swap_lock);
}