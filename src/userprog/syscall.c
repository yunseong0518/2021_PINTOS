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

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
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
      tid = process_execute(file_name);

      if (get_child_process(tid) == NULL)
        (f->eax) = -1;
      else if (get_child_process(tid)->is_use_memory)
        (f->eax) = tid;
      else
        (f->eax) = -1;
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
      syscall_check_vaddr(f->esp + 16);
      name = *(char **)(f->esp + 16);
      unsigned size;
      syscall_check_vaddr(f->esp + 20);
      size = *(unsigned *)(f->esp + 20);
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
      char *name;
      syscall_check_vaddr(f->esp + 4);
      name = *(char **)(f->esp + 4);
      if(name == NULL) syscall_exit(-1);
      int fd;
      fd = thread_current()-> fd_count++;
      thread_current()->fd_table[fd] = filesys_open(name);
      if (thread_current()->fd_table[fd] == NULL)
        f->eax = -1;
      else 
        f->eax = fd;
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
      int length;
      syscall_check_vaddr(f->esp + 12);
      length = *(int *)(f->esp + 12);
      struct file* fi;
      fi = thread_current()->fd_table[fd];
      if (fi == NULL)
        (f->eax) = -1;
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
        if (fi == NULL)
          (f->eax) = -1;
        else
          (f->eax) = file_write(fi, buffer, size);
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
  }
}
