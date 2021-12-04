#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "vm/spt.h"

void syscall_init (void);
void syscall_exit (int);
void syscall_munmap (int);
void syscall_check_vaddr(const void *);

struct mmap_entry
{
  struct list_elem elem;
  int mapid;
  tid_t tid;
  void* upage;
  bool dirty;
  struct file* file;
  int page_cnt;
};

struct lock filesys_lock;
struct list mmap_table;

#endif /* userprog/syscall.h */
