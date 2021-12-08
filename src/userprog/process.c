#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "lib/string.h"
#include "userprog/syscall.h"
#include "vm/spt.h"
#include "userprog/exception.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

struct thread* get_child_process (int pid)
{
  struct list_elem *e;
  struct thread* cur;
  cur = thread_current();
  for (e = list_begin(&cur->child_list); e != list_end(&cur->child_list); e = list_next(e)) {
    if (list_entry(e, struct thread, child_elem)->tid == pid) {
      return list_entry(e, struct thread, child_elem);
    }
  }
  return NULL;
}

void remove_child_process (struct thread *cp)
{
  list_remove(&cp->child_elem);
}

struct shared_param {
  char *fn_copy;
  struct semaphore load_sema;
  bool success;
};

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
//  printf("call process_execute with $%s\n", file_name);

  struct shared_param param;

  // parsing file name
  char file_name_origin[128];
  char *program_name;
  char *ptr;

  strlcpy(file_name_origin, file_name, strlen(file_name)+1);
  program_name = strtok_r(file_name_origin, " ", &ptr);

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  param.fn_copy = fn_copy;
  sema_init(&param.load_sema, 0);
  param.success = false;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (program_name, PRI_DEFAULT, start_process, &param);

  if (tid == TID_ERROR) {
    if (fn_copy != NULL)
      palloc_free_page (fn_copy);
  }
  else {
    // printf("before load sema down %d, %s\n", thread_current()->tid, thread_current()->name);
    sema_down(&param.load_sema);
    // printf("after load sema down %d, %s\n", thread_current()->tid, thread_current()->name);
    if (!param.success) {
      return -1;
    }
  }
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *param_)
{
  struct shared_param *param = param_;
  char *file_name = param->fn_copy;
  struct intr_frame if_;
  bool success;
  // variable for parsing file name
  char file_name_no_double[128];
  char *program_name;
  char *real_program_name;
  char argument[128];
  char *argu_address[128];
  int argu_num;
  int argu_size;
  char *tmp_ptr;
  char *ptr;
  char *token;

  argu_num = 0;
  argu_size = 0;

  int i, j;
  for (i = 0, j = 0; i < strlen(file_name); i++) {
    if (i == 0) {
      file_name_no_double[j++] = file_name[i];
    }
    else {
      if (file_name[i - 1] == ' ' && file_name[i] == ' ')
        continue;
      else {
        file_name_no_double[j++] = file_name[i];
      }
    }
  }
  file_name_no_double[j] = '\0';
  // parsing file name for program name
  program_name = strtok_r(param->fn_copy, " ", &tmp_ptr);
  real_program_name = strtok_r(file_name_no_double, " ", &ptr);
  argu_num++;
  argu_size += strlen(program_name) + 1;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (program_name, &if_.eip, &if_.esp);

  if (success) {


  // parsing all argument
  do {
    token = strtok_r(NULL, " ", &ptr);
    if (token != NULL) {
      argu_num++;
      argu_size += strlen(token) + 1;
    }
  } while (token);

  // push argument
  int argu_num_tmp = argu_num;
  int program_name_length = strlen(program_name);

  for (i = argu_size - 1; i >= 0; i--) {
    argument[i] = file_name_no_double[i];
    if_.esp--;
    *(char *)if_.esp = argument[i];
    if (argument[i] == '\0' && i != argu_size - 1) {
      argu_address[--argu_num_tmp] = if_.esp + 1;
    }
  }
  argu_address[--argu_num_tmp] = if_.esp;

  //printf("tid : %d\n", thread_tid());
 // hex_dump( if_.esp , if_.esp , PHYS_BASE - if_.esp , true );


  // align
  for (i = 0; i < 4 - argu_size % 4; i++) {
    if_.esp--;
    *(uint8_t *)if_.esp = 0;
  }

  // null
  if_.esp -= 4;
  *(char **)if_.esp = 0;

  // push argument address
  for (i = argu_num - 1; i >= 0; i--) {
    if_.esp -= 4;
    *(char **)if_.esp = argu_address[i];
  }

  // argv
  if_.esp -= 4;
  *(char ***)if_.esp = (char **)(if_.esp + 4);

  // argc
  if_.esp -= 4;
  *(int *)if_.esp = argu_num;

  // return address
  if_.esp -= 4;
  *(int *)if_.esp = 0;

  }
  

  /* If load failed, quit. */
  if (param->fn_copy != NULL)
    palloc_free_page (param->fn_copy); 
  param->success = success;
  sema_up(&param->load_sema);
  if (!success) {
    thread_exit ();
  }
  

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct thread* t;
  struct list_elem *e;
  struct thread* cur;
  int status;
  cur = thread_current();
  // printf("process wait %d, %s\n", cur->tid, cur->name);
  for (e = list_begin(&cur->child_list); e != list_end(&cur->child_list); e = list_next(e)) {
    t = list_entry(e, struct thread, child_elem);
    if (t->tid == child_tid) {
      //printf("before exit sema down %d, %s\n", cur->tid, cur->name);
      sema_down(&t->exit_sema);
      //printf("after exit sema down %d, %s\n", cur->tid, cur->name);
      status = t->exit_status;
      //printf("exit_status : %d, %s\n", status, cur->name);
      list_remove(&t->child_elem);
      sema_up(&t->mem_sema);
      return status;
    }
  }
    return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  printf("[process_exit | %d] begin\n", thread_tid());
  struct thread *cur = thread_current ();
  uint32_t *pd;
  // printf("call process_exit in %d\n", cur->tid);

  struct list_elem *e;
  for (e = list_begin(&cur->child_list); e != list_end(&cur->child_list); e = list_next(e)) {
    struct thread *t;
    t = list_entry(e, struct thread, child_elem);
    // printf("wait for %d\n", t->tid);
    process_wait(t->tid);
  }

  int i;
  for (i = 2; i < FD_MAX; i++) {
    if (cur->fd_table[i] != NULL)
      file_close(cur->fd_table[i]);
    cur->fd_table[i] = NULL;
  }
  for (e = list_begin(&mmap_table); e != list_end(&mmap_table); e = list_next(e)) {
    struct mmap_entry* me;
    me = list_entry(e, struct mmap_entry, elem);
    if (me->tid == thread_tid()) {
      syscall_munmap(me->mapid);
    }
  } 

    file_close(cur->running_file);
    // printf("finish file_close in %s\n", cur->name);
    sema_up(&cur->exit_sema);
    sema_down(&cur->mem_sema);
    //lock_release(&evict_lock);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;

      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
  printf("[process_exit | %d] finish\n", thread_tid());
    
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  // printf("call load\n");

  lock_acquire(&t->file_open_lock);
  // printf("finish lock_acquire\n");
  /* Open executable file. */
  // printf("\topen file %s in %s\n", file_name, t->name);
  file = filesys_open (file_name);

  // printf("finish filesys_open\n");
  

  if (file == NULL) 
    {
      lock_release(&t->file_open_lock);
      // printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  t->running_file = file;
  file_deny_write(file);
  // printf("\tfinish deny %s in %s\n", file_name, t->name);
  // printf("\t\tfile_deny : %d\n", get_deny_write(file));
  lock_release(&t->file_open_lock);

  // printf("finish file_deny_write\n");

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  // file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  #if 0
  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = frame_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          if (kpage != NULL)
            frame_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          if (kpage != NULL)
            frame_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
  #endif
  #if 1
  lock_acquire(&fault_lock);
  while (read_bytes > 0 || zero_bytes > 0) {
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    spt_add_entry (&thread_current()->spt, upage, page_read_bytes, page_zero_bytes, file, writable, ofs, false);
    //printf("U : %p, f : %p\n", upage, file);

    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
    ofs += page_read_bytes;
  }
  lock_release(&fault_lock);
  #endif
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  printf("[setup_stack | %d ] begin\n", thread_tid());
  lock_acquire(&fault_lock);
  printf("[setup_stack | %d] finish wait fault\n", thread_tid());
  uint8_t *kpage;
  
  bool success = false;
  spt_add_entry (&thread_current()->spt,((uint8_t *) PHYS_BASE) - PGSIZE, 0, PGSIZE, NULL, true, 0, true);
  kpage = spt_alloc(&thread_current()->spt, ((uint8_t *) PHYS_BASE) - PGSIZE, PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else {
        if (kpage != NULL)
          frame_free_page (kpage);
      }
    }
  lock_release(&fault_lock);
    //printf("stack setup u : %p, k : %p\n", ((uint8_t *) PHYS_BASE) - PGSIZE, kpage);
    //printf("call swap in k : %p\n", kpage);
    //swap_in(&thread_current()->spt, kpage);
  printf("[setup_stack | %d] finish\n", thread_tid());
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
