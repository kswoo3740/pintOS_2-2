#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <devices/shutdown.h>
#include <filesys/filesys.h>
#include <filesys/file.h>
#include <devices/input.h>
#include "userprog/process.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "vm/page.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);


void halt (void);
void exit (int status);
bool create (const char *file, unsigned int initial_size);
bool remove (const char *file);
tid_t exec (char *process_name);
int wait (tid_t tid);
int write(int fd, void* buffer, unsigned size);
int read(int fd, void* buffer, unsigned size);
int file_size(int fd);
int open(const char* file);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

void get_argument(unsigned int *esp, int *arg, int argc);

struct vm_entry* check_address(void *addr, void *esp UNUSED);
void check_valid_buffer (void *buffer, unsigned int size, void *esp, bool to_write);
void check_valid_string (const void *str, void *esp);

int mmap (int fd, void *addr);
void munmap (int mapping);
void do_munmap (struct mmap_file *mmap_f);

void
syscall_init (void) 
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  unsigned int *esp = (unsigned int*)(f->esp);  //stack pointer
  check_address(esp, esp);
  int sys_n = *(int*)esp;  //store system call number
  int argument[4];
  
  esp++; //스택 값 증가
  check_address(esp, esp);
  switch(sys_n)
  {
      //get_argument를 통해 각 함수에 필요한 인자의 갯수 리턴 받음
      case SYS_HALT:
          halt();
          break;
      case SYS_EXIT:
          {
            get_argument(esp, argument, 1);
            int status = argument[0];

            exit(status);
          }
          break;

      case SYS_EXEC:
          {
            get_argument(esp, argument, 1);

            char *filename = (char*)argument[0];
            check_valid_string (filename, esp);

            f->eax = exec(filename);
          }
          break;

      case SYS_WAIT:
          {
            get_argument(esp, argument, 1);

            int tid = argument[0];
            
            f->eax = wait(tid);
          }
          break;

      case SYS_CREATE:
          {
            get_argument(esp, argument, 2);

            char *filename = (char*)argument[0];
            unsigned int initial_size = (unsigned int)argument[1];

            check_valid_string (filename, esp);
            
            f->eax = create(filename, initial_size);
          }
          break;

      case SYS_REMOVE:
          {
            get_argument(esp, argument, 1);

            char *filename = (char*)argument[0];

            check_valid_string (filename, esp);

            f->eax = remove(filename);
          }
          break;

      case SYS_OPEN:
          {
            get_argument(esp, argument, 1);
          
            char *filename = (char*)argument[0];

            check_valid_string (filename, esp);

            f->eax = open(filename);
          }
          break;

      case SYS_FILESIZE:
          {
            get_argument(esp, argument, 1);

            int fd = argument[0];
          
            f->eax = file_size(fd);
          }
          break;

      case SYS_READ:
          {
            get_argument(esp, argument, 3);

            int fd = argument[0];
            void *buffer = (void*)argument[1];
            unsigned int size = (unsigned int)argument[2];

            check_valid_buffer (buffer, size, esp, true);

            f->eax = read(fd, buffer, size);
          }
          break;

      case SYS_WRITE:
          {
            get_argument(esp, argument, 3);

            int fd = argument[0];
            void *buffer = (void*)argument[1];
            unsigned int size = (unsigned int)argument[2];

            check_valid_buffer (buffer, size, esp, false);

            f->eax = write(fd, buffer, size);
          }
          break;

      case SYS_SEEK:
          {
            get_argument(esp, argument, 2);

            int fd = argument[0];
            unsigned int position = (unsigned int)argument[1];

            seek(fd, position);
          }
          break;

      case SYS_TELL:
          {
            get_argument(esp, argument, 1);

            int fd = argument[0];

            f->eax = tell(fd);
          }
          break;

      case SYS_CLOSE:
          {
            get_argument(esp, argument, 1);

            int fd = argument[0];

            close(fd);
          }
          break;

      case SYS_MMAP:
          {
            get_argument (esp, argument, 2);

            int fd = (int)argument[0];
            char *buffer = (char*)argument[1];

            f->eax = mmap (fd, buffer);
          }
          break;

      case SYS_MUNMAP:
          {
            get_argument (esp, argument, 1);

            int mapping  = (int)argument[0];

            munmap (mapping);
          }
          break;
  }

  //thread_exit ();
}

struct vm_entry*
check_address (void *addr, void *esp UNUSED)
{ 
  //check address is in user address range
  if ((unsigned int)addr <= 0x8048000 || (unsigned int)addr >= 0xc0000000) 
      exit(-1);
  
  struct vm_entry *entry = find_vme (addr);
  if (entry == NULL) exit(-1);
  if (entry) 
    handle_mm_fault (entry);  

  return entry;
}

void
check_valid_buffer (void *buffer, unsigned int size, void *esp, bool to_write)
{
  unsigned int i;
  struct vm_entry *entry;
  void *addr = buffer;

  for (i = 0; i < size; i++) 
  {
    entry = check_address (addr, esp);
    if (to_write && !entry->writable)  //check entry is null and writable
    {
      exit(-1);
    }
    addr++;
  }
}

void
check_valid_string (const void *str, void *esp)
{
  void *addr = (void*)str;  
/*
  while (*(char*)addr != '\0')
  {
    check_address (addr, esp);
    addr++;
  }
*/
  check_address (addr, esp);
}

void
get_argument (unsigned int *esp, int *arg, int argc)
{
  int i;
  for (i = 0; i < argc; i++)
  {
    check_address((void*)esp, (void*)esp);
    arg[i] = (int)*(esp);
    esp++;  //insert esp address to kernel stack
  }
}

void
halt(void)
{
  //shutdown system
  shutdown_power_off();
}

void
exit (int status)
{
  //exit thread
  struct thread *thread_cur = thread_current();  //현재 thread 를 받아옴
  printf ("%s: exit(%d)\n", thread_cur->name, status);  //종료상태 출력
  thread_cur->exit_status = status;  //종료상태 저장
  thread_exit();
}

bool
create (const char *file, unsigned int initial_size)
{
  lock_acquire(&filesys_lock);  //lock을 걸 어줌
  bool is_success = filesys_create(file, initial_size);  //create 성공 여부
  lock_release(&filesys_lock);  //lock을 풀어줌

  return is_success;
}

bool
remove (const char *file)
{
  lock_acquire(&filesys_lock);  //lock을 걸 어줌
  bool is_success = filesys_remove(file);  //remove성공여부
  lock_release(&filesys_lock);  //lock을 풀어줌

  return is_success;
}

tid_t
exec (char *process_name)
{
  tid_t exec_process_tid = process_execute(process_name);  //exec되는 process tid 
  struct thread *exec_process = get_child_process(exec_process_tid);

  if (exec_process)
    {
      sema_down(&exec_process->load_sema);
      
        if (exec_process->is_load)
        {
          return exec_process_tid;
        }
        else
        {
          return -1;
        }
    }
  else
  {
    return -1;
  }
}

int
wait (tid_t tid)
{
  return process_wait(tid);
}

int
open (const char *file_name)
{
  lock_acquire(&filesys_lock);  //lock을 걸어줌
  struct file *open_file_name = filesys_open(file_name);  //open할 파일

  if (!open_file_name)
  {
    lock_release(&filesys_lock);  //lock을 풀어줌
    return -1;
  }

  int open_file_fd = process_add_file(open_file_name);
  lock_release(&filesys_lock);  //lock을 풀어줌

  return open_file_fd;
}

int 
file_size (int fd)
{
  lock_acquire(&filesys_lock);  //lock을 걸어줌
  struct file *check_file = process_get_file(fd);  //size를 확인할 파일
  if (!check_file)
  {
    lock_release(&filesys_lock);  // lock을 풀어줌
    return -1;
  }
  int file_size = file_length(check_file);
  lock_release(&filesys_lock);  //lock을 풀어줌

  return file_size;
}

int
read (int fd, void *buffer, unsigned size)
{
  lock_acquire(&filesys_lock);  //lock을 걸어줌

  if (fd == 0)  //stdin
  {
    unsigned int i;
    
    for (i = 0; i < size; i++)
    {
      ((char*)buffer)[i] = input_getc();
    }

    lock_release(&filesys_lock);  //lock을 풀어줌

    return size;
  }

  struct file *file_name = process_get_file(fd);
  if(!file_name)
  {
    lock_release(&filesys_lock);  //lock을 풀어줌
    return -1;  
  }
  
  int file_size = file_read(file_name, buffer, size);  //읽어올 파일의 크기
  lock_release(&filesys_lock);
  
  return file_size;
}

int
write (int fd, void *buffer, unsigned size)
{
  lock_acquire(&filesys_lock);  //lock을 걸어줌
  

  if (fd == 1)
  {
    putbuf(buffer, size);
    lock_release(&filesys_lock);  //lock을 풀어줌

    return size;
  }

  struct file *file_name = process_get_file(fd);
  if(!file_name)
  {
    lock_release(&filesys_lock);  //lock을 풀어줌
    return -1;
  }

  int file_size = file_write(file_name, buffer, size);
  lock_release(&filesys_lock);  //lock을 풀어줌 

  return file_size;
}

void
seek (int fd, unsigned int position)
{
  lock_acquire(&filesys_lock);  //lock을 걸어줌

  struct file *file_name = process_get_file(fd);
  if (!file_name)
  {
    lock_release(&filesys_lock);  //lock을 풀어줌
    return;
  }
  file_seek(file_name, (off_t)position);
  lock_release(&filesys_lock);  //lock을 풀어줌
}

unsigned
tell (int fd)
{
  lock_acquire(&filesys_lock);  //lock을 걸어줌

  struct file *file_name = process_get_file(fd);
  
  if (!file_name)
  {
    lock_release(&filesys_lock);  //lock을 풀어줌
    return -1;
  }

  off_t offset = file_tell(file_name);
  lock_release(&filesys_lock);  //lock을 풀어줌
  
  return offset; 
}

void
close (int fd)
{
  //lock_acquire(&filesys_lock);  //lock을 걸어줌
  process_close_file(fd);
  //lock_release(&filesys_lock);  //lock을 풀어줌
}

int
mmap (int fd, void *addr)
{
  struct file *fp = process_get_file (fd);  //Get file pointer from fd

  if (!fp)  //Check valid file pointer
    return -1;

  struct mmap_file *mmap_fp = (struct mmap_file*) malloc (sizeof(struct mmap_file));
  
  if (pg_ofs(addr) != 0)  //align mmap
    return -1;

  if (addr == 0)  //protect kernel memory
    return -1;  

  if (mmap_fp == NULL)  //Check valid allocate
    return -1;

  int mapid = thread_current()->mapid;
  struct file *fp_reopen = file_reopen (fp);   //Reopen file pointer

  thread_current()->mapid++;  

  /*Initialize mmap_fp*/
  mmap_fp->file = fp_reopen; 
  mmap_fp->mapid = mapid;
  list_init (&mmap_fp->vme_list);

  int file_len = file_length (fp_reopen);

  if (fp_reopen == NULL)
    return -1;

  size_t offset = 0;

  while (file_len > 0)
  {
    int read_bytes = file_len;

    if (file_len > PGSIZE)
      read_bytes = PGSIZE;

    int zero_bytes = PGSIZE - read_bytes;

    if (find_vme (addr) != NULL)
    {
      munmap (mapid);
      return -1;
    }  

    struct vm_entry *entry = (struct vm_entry*) malloc (sizeof(struct vm_entry));

    if (!entry)
    {
      munmap (mapid);
      return -1;
    }

    /*Initialize entry*/
    entry->vaddr = addr;
    entry->file = fp_reopen;
    entry->offset = offset;
    entry->read_bytes = read_bytes;
    entry->zero_bytes = zero_bytes;
    entry->type = VM_FILE;
    entry->writable = true;
    entry->is_loaded = false;

    list_push_back (&mmap_fp->vme_list, &entry->mmap_elem);
    insert_vme (&thread_current()->vm, entry);

    /*Change values after mapping page*/
    file_len -= read_bytes;
    offset += read_bytes;
    addr += PGSIZE;
  }
  
  list_push_back (&thread_current()->mmap_list, &mmap_fp->elem);

  return mapid;
}

void
munmap (int mapping)
{
  struct list_elem *e;
  
  /*Find mapid which is equal with mapping or remove all if mapping == -1*/
  for (e = list_begin(&thread_current()->mmap_list); e != list_end(&thread_current()->mmap_list); e = list_next(e))
  {
    struct mmap_file *mmap_fp = list_entry (e, struct mmap_file, elem);

    if (mmap_fp->mapid == mapping || mapping == -1)
    {
      do_munmap (mmap_fp);

      if (mmap_fp->file)
      {
        file_close (mmap_fp->file);
      }

      list_remove (&mmap_fp->elem);
      //free (mmap_fp);
    }  
  }
}

void
do_munmap (struct mmap_file *mmap_fp)
{
  struct list_elem *e;

  for (e = list_begin(&mmap_fp->vme_list); e != list_end(&mmap_fp->vme_list); e = list_next(e))
  {
    struct vm_entry *entry = list_entry (e, struct vm_entry, mmap_elem);

    if (entry != NULL && entry->is_loaded)
    {
      if (pagedir_is_dirty (thread_current()->pagedir, entry->vaddr))
      {
        lock_acquire (&filesys_lock);
        file_write_at (entry->file, entry->vaddr, entry->read_bytes, entry->offset);
        lock_release (&filesys_lock);
      }

      palloc_free_page (pagedir_get_page (thread_current()->pagedir, entry->vaddr));
      pagedir_clear_page (thread_current()->pagedir, entry->vaddr);
    }

    list_remove (&entry->mmap_elem);

    delete_vme (&thread_current()->vm, entry);
  }
}
