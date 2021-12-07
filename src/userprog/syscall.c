#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/string.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "vm/spt.h"
#include "threads/vaddr.h"
#include <list.h>

static void syscall_handler (struct intr_frame *);

static int mapid_count;

void
syscall_init (void) 
{
  list_init(&mmap_table);
  mapid_count = 1;
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void syscall_exit(int status) {
    thread_current()->exit_status = status;
    printf("%s: exit(%d)\n", thread_current()->name, status);
    thread_exit();
}

void syscall_munmap (int mapid) {
  struct list_elem *e;
  struct mmap_entry *me;
  bool find_me;
  //do {
    find_me = false;
    for (e = list_begin(&mmap_table); e != list_end(&mmap_table); e = list_next(e)) {
      me = list_entry (e, struct mmap_entry, elem);
      //printf("munmap get list_entry\n");
      if (me->mapid == mapid) {
        find_me = true;
        break;
      }
      //printf("unfind mapid\n");
    }
    struct spt_entry* se;
    int i;
    for (i = 0; i < me->page_cnt; i++) {
      se = spt_lookup(&thread_current()->spt, me->upage + i * PGSIZE);
      ASSERT(se != NULL);
      //printf("spt_lookup\n");
      if (me->dirty == true) {
        file_write_at(me->file, me->upage + i * PGSIZE, se->page_read_bytes, se->ofs);
      }
    }

    spt_remove_entry(&thread_current()->spt, me->upage);
    file_close (se->file);
    list_remove(&me->elem);
}

void syscall_check_vaddr(const void *vaddr) {
  if (!is_user_vaddr(vaddr))
     syscall_exit(-1);
}

static void
syscall_handler (struct intr_frame *f) 
{
  syscall_check_vaddr(f->esp);
  switch((uint32_t)*(uint32_t*)(f->esp)) {
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXIT:
    { 
      int status;
      syscall_check_vaddr(f->esp + 4);
      status = *(int *)(f->esp + 4);
      syscall_exit(status);
      break;
    }
    case SYS_EXEC:
    {
      char *file_name;
      tid_t tid;
      syscall_check_vaddr(f->esp + 4);
      file_name = *(char **)(f->esp + 4);
      lock_acquire(&filesys_lock);
      f->eax = process_execute(file_name);
      lock_release(&filesys_lock);
      //printf("sys execute fin %s, %d\n", file_name, f->eax);
      break;
    }
    case SYS_WAIT:
    {
      tid_t tid;
      syscall_check_vaddr(f->esp + 4);
      tid = (tid_t)*(tid_t *)(f->esp + 4);
      (f->eax) = process_wait(tid);
      break;
    }
    case SYS_CREATE:
    {
      char *name;
      syscall_check_vaddr(f->esp + 4);
      name = *(char **)(f->esp + 4);
      unsigned size;
      syscall_check_vaddr(f->esp + 8);
      size = *(unsigned *)(f->esp + 8);
      if(name == NULL) syscall_exit(-1); 
      else {
        lock_acquire(&filesys_lock);
        (f->eax) = filesys_create(name, size);
        lock_release(&filesys_lock);
      }
      break;
    }
    case SYS_REMOVE:
    {
      char *name;
      syscall_check_vaddr(f->esp + 4);
      name = *(char **)(f->esp + 4);
      if(name == NULL) syscall_exit(-1); 
      (f->eax) = filesys_remove(name);
      break;
    }
    case SYS_OPEN:
    {
      char *name;
      syscall_check_vaddr(f->esp + 4);
      name = *(char **)(f->esp + 4);
      if(name == NULL) syscall_exit(-1);
      int fd;
      fd = -1;
      int i;
      for (i = 3; i < FD_MAX; i++) {
        if (thread_current()->fd_table[i] == NULL) {
          fd = i;
          break;
        }
      }
      if (fd == -1) {
        f->eax = -1;
        break;
      }
      struct file* file;
      lock_acquire(&filesys_lock);
      file = filesys_open(name);
      lock_release(&filesys_lock);


      thread_current()->fd_table[fd] = file;
      //printf("open with file %s : %p\n", name, thread_current()->fd_table[fd]);
      // int k;
      // k = 1;
      // do {
      //   thread_current()->fd_table[fd] = filesys_open(name);
      //   k++;
      // } while (thread_current()->fd_table[fd] == NULL && k < FD_MAX);
      // // filesys open incomplete
      
      if (thread_current()->fd_table[fd] == NULL) {
        f->eax = -1;
      }
      else {
        f->eax = fd;
      }

      //lock_release(&filesys_lock);
      break;
    }
    case SYS_FILESIZE: 
    {
      int fd;
      syscall_check_vaddr(f->esp + 4);
      fd = *(int *)(f->esp + 4);
      struct file* fi;
      fi = thread_current()->fd_table[fd];
      if (fi == NULL)
        f->eax = -1;
      else
        f->eax = file_length(fi);
      break;
    }
    case SYS_READ:
    {
      int fd;
      syscall_check_vaddr(f->esp + 4);
      fd = *(int *)(f->esp + 4);
      char* buf;
      syscall_check_vaddr(f->esp + 8);
      buf = *(char **)(f->esp + 8);
      syscall_check_vaddr(buf);
      int length;
      syscall_check_vaddr(f->esp + 12);
      length = *(int *)(f->esp + 12);
      struct file* fi;
      fi = thread_current()->fd_table[fd];
      //printf("sys_read fd : %d, file : %p\n", fd, fi);
      if (fi == NULL) {
        syscall_exit(-1);
      }
      else {
        if (fd == 0) {
          int i;
          for (i = 0; i < length; i++) {
            buf[i] = input_getc();
          }
          (f->eax) = i;
        }
        else {
          lock_acquire(&filesys_lock);
          (f->eax) = file_read(fi, buf, length);
          lock_release(&filesys_lock);
          //printf("sys_read complete %d\n", f->eax);
        }
      }
      break;
    }
    case SYS_WRITE:
    {
      int fd;
      syscall_check_vaddr(f->esp + 4);
      fd = (int)*(int *)(f->esp + 4);
      void *buffer;
      syscall_check_vaddr(f->esp + 8);
      buffer = (void *)*(char **)(f->esp + 8);
      int size;
      syscall_check_vaddr(f->esp + 12);
      size = (int)*(int *)(f->esp + 12);
      if (fd == 1) {
        // print on STDOUT
        putbuf(buffer, size);
        (f->eax) = size;
      } else {
        struct file *fi;
        fi = thread_current()->fd_table[fd];
        if (fi == NULL) {
          (f->eax) = -1;
        }
        else{
          //if(thread_current()->fd_table[fd]->deny_write){
          //  file_deny_write(fi);
          //}
          // printf("\ttry file_write in SYS_WRITE in %s\n", thread_current()->name);
          lock_acquire(&filesys_lock);
          (f->eax) = file_write(fi, buffer, size);
          lock_release(&filesys_lock);
          // printf("\tfinish file_write in SYS_WRITE in %s\n", thread_current()->name);
        }
      }
      break;
    }
    case SYS_SEEK:
    {
      int fd;
      syscall_check_vaddr(f->esp + 4);
      fd = *(int *)(f->esp + 4);
      unsigned pos;
      syscall_check_vaddr(f->esp + 8);
      pos = *(unsigned *)(f->esp + 8);
      struct file* fi;
      fi = thread_current()->fd_table[fd];
      file_seek(fi, pos);
      break;
    }
    case SYS_TELL:
    {
      int fd;
      syscall_check_vaddr(f->esp + 4);
      fd = *(int *)(f->esp + 4);
      struct file* fi;
      fi = thread_current()->fd_table[fd];
      (f->eax) = file_tell(fi);
      break;
    }
    case SYS_CLOSE:
    {
      int fd;
      syscall_check_vaddr(f->esp + 4);
      fd = *(int *)(f->esp + 4);
      struct file* fi;
      fi = thread_current()->fd_table[fd];
      if(fi == NULL) 
        syscall_exit(-1);
      thread_current()->fd_table[fd] = NULL;
      thread_current()->fd_count--;
        file_close(fi);
      
      break;
    }
    case SYS_MMAP:
    {
      int fd;
      void *addr;
      syscall_check_vaddr(f->esp + 4);
      fd = *(int *)(f->esp + 4);
      syscall_check_vaddr(f->esp + 8);
      addr = *(void **)(f->esp + 8);
      //printf("mmap with fd : %d, addr : %p, tid : %d\n", fd, addr, thread_tid());
      if (addr == NULL) {
        (f->eax) = -1;
        break;
      }
      if ((int)addr & 0x00000FFF) {
        (f->eax) = -1;
        break;
      }
        
      off_t length;
      struct file* file;
      off_t ofs;
      ofs = 0;
      lock_acquire(&filesys_lock);
      file = thread_current()->fd_table[fd];
      struct file* file_re;
      if (file == NULL) {
        lock_release(&filesys_lock);
        (f->eax) = -1;
        break;
      }
      length = file_length(file);
      file_re = file_reopen(file);


      lock_release(&filesys_lock);
      if (length == 0) {
        (f->eax) = -1;
        break;
      }
      bool spt_success;
      spt_success = true;
      int page_cnt;
      page_cnt = 0;
      while (length > 0) {
        int page_read_bytes;
        int page_zero_bytes;
        if (length > PGSIZE) {
          page_read_bytes = PGSIZE;
          page_zero_bytes = 0;
        } else {
          page_read_bytes = length;
          page_zero_bytes = PGSIZE - length;
        }
        //printf("mmap u : %p\n", addr + ofs);
        spt_success &= spt_add_entry(&thread_current()->spt, addr + ofs, page_read_bytes, page_zero_bytes, file_re, false, ofs, false);
        length -= PGSIZE;
        ofs += PGSIZE;
        page_cnt++;
      }
      if (spt_success == false) {
        length = file_length(file);
        ofs = 0;
        while(length > 0) {
          spt_dealloc(&thread_current()->spt, addr + ofs);
          ofs += PGSIZE;
          length -= PGSIZE;
        }
        (f->eax) = -1;
        break;
      }
      struct mmap_entry *me;
      me = malloc(sizeof(struct mmap_entry));
      me->tid = thread_current()->tid;
      me->mapid = mapid_count++;
      me->upage = addr;
      me->file = file_re;
      me->dirty = false;
      me->page_cnt = page_cnt;
      list_push_back(&mmap_table, &me->elem);
      (f->eax) = me->mapid;
      break;
    }
    case SYS_MUNMAP:
    {
      //printf("start munmap\n");
      int mapid;
      syscall_check_vaddr(f->esp + 4);
      mapid = *(int *)(f->esp + 4);
      //printf("munmap get mapid\n");
      syscall_munmap(mapid);
      //} while (find_me);
          //printf("find mapid\n");
          //printf("upage : %p\n", me->upage);
      //printf("finish munmap\n");
      break;
    }
  }
}
