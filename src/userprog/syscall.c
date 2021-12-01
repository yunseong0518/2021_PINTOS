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
#include "threads/vaddr.h"
#include <list.h>

static void syscall_handler (struct intr_frame *);

static int mapid_count;

struct mmap_entry
{
  struct list_elem elem;
  int mapid;
  tid_t tid;
  void* upage;
};

struct list mmap_table;

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
      f->eax = process_execute(file_name);
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
      else (f->eax) = filesys_create(name, size);
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
      lock_acquire(&filesys_lock);
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
        lock_release(&filesys_lock);
        break;
      }
      thread_current()->fd_table[fd] = filesys_open(name);
      //printf("open with file : %p\n", thread_current()->fd_table[fd]);
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
      lock_release(&filesys_lock);
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
      lock_acquire(&filesys_lock);
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
      if (fi == NULL) {
        lock_release(&filesys_lock);
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
          (f->eax) = file_read(fi, buf, length);
        }
      }
      lock_release(&filesys_lock);
      break;
    }
    case SYS_WRITE:
    {
      lock_acquire(&filesys_lock);
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
          (f->eax) = file_write(fi, buffer, size);
          // printf("\tfinish file_write in SYS_WRITE in %s\n", thread_current()->name);
        }
      }
      lock_release(&filesys_lock);
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
      //printf("mmap with fd : %d, addr : %p\n", fd, addr);
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
      if (file == NULL) {
        (f->eax) = -1;
        break;
      }
      length = file_length(file);
      printf("file : %p, length : %d\n", file, length);
      if (length == 0) {
        (f->eax) = -1;
        break;
      }
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
        spt_add_entry(&thread_current()->spt, addr + ofs, page_read_bytes, page_zero_bytes, file, true, ofs, false);
        length -= PGSIZE;
        ofs += PGSIZE;
      }
      lock_release(&filesys_lock);
      struct mmap_entry *me;
      me = malloc(sizeof(struct mmap_entry));
      me->tid = thread_current()->tid;
      me->mapid = mapid_count++;
      me->upage = addr;
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
      struct list_elem *e;
      for (e = list_begin(&mmap_table); e != list_end(&mmap_table); e = list_next(e)) {
        struct mmap_entry *me;
        me = list_entry (e, struct mmap_entry, elem);
        //printf("munmap get list_entry\n");
        if (me->mapid == mapid) {
          //printf("find mapid\n");
          //printf("upage : %p\n", me->upage);
          spt_lookup(&thread_current()->spt, me->upage);
          //printf("spt_lookup\n");
          if (spt_lookup(&thread_current()->spt, me->upage) == NULL) {
            //printf("spt lookup NULL\n");
            spt_free (&thread_current()->spt, me->upage);
          } else {
            //printf("spt lookup exist\n");
            spt_remove_entry (&thread_current()->spt, me->upage);
          }
        }
        //printf("unfind mapid\n");
      }
      //printf("finish munmap\n");
      break;
    }
  }
}
