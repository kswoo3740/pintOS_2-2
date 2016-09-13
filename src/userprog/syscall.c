#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <devices/shutdown.h>

static void syscall_handler (struct intr_frame *);

void check_address(void *addr);
void get_argument(unsigned int *esp, unsigend int *arg, int argc);
void sys_halt(void);
void sys_exit(int status);
bool sys_create(const char *file, unsigned int initial_size);
bool sys_remove(const char *file);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  unsigned int *esp = (unsigned int*)(f->esp);  //stack pointer
  check_address(esp);
  int sys_n = *(int*)esp;  //store system call number
  unsigned int *argument[5];
  
  esp = esp + 1; //increase stack pointer
  check_address(esp);

  switch(sys_n)
  {
      case SYS_HALT:
          sys_halt();
          break;
      case SYS_EXIT:
          {
            get_argument(esp, argument, 1);
            int status = (int)*(argument[0]);

            sys_exit(status);
          }
          break;
      case SYS_EXEC:

      case SYS_WAIT:

      case SYS_CREATE:
          {
            get_argument(esp, argument, 2);

            char *filename = (char*)*(argument[0]);
            unsigned int initial_size = (int)*(argument[1]);
            
            f->eax = sys_create(filename, initial_size);
          }

      case SYS_REMOVE:
          {
            get_argument(esp, argument, 1);

            char *filename = (char*)*(argument[0]);

            f->eax = sys_remove(filename);
          }

      case SYS_OPEN:

      case SYS_FILESIZE:

      case SYS_READ:

      case SYS_WRITE:

      case SYS_SEEK:

      case SYS_SEEK:

      case SYS_TELL:

      case SYS_CLOSE:
  }

  printf ("system call!\n");
  thread_exit ();
}

void
check_address (void *addr)
{ 
  //check address is in user address range
  if ((unsigned int)addr <= 0x8048000 || (unsigned int)addr >= 0xc0000000)
      sys_eixt(-1);
}

void
get_argument (unsigned int *esp, unsigned int *arg, int argc)
{
  int i;
  esp = esp + 1;
  for (i = 0; i < argc; i++)
  {
    check_address((void*)esp);
    arg[i] = esp;
    esp = esp + 1;  //insert esp address to kernel stack
  }
}

void
sys_halt(void)
{
  //shutdown system
  shutdown_power_off();
}

void
sys_exit (int status)
{
  //exit thread
  struct thread *thread_cur = thread_current();
  printf ("%s : exit(%d)n", thread_cur->name, status);
  
  thread_exit();
}

bool
sys_create (const char *file, unsigned int initial_size)
{
  check_address((void*)file);  //if argument is pointer

  bool result = filesys_remove(file);

  return result;
}

bool
sys_remove (const char *file)
{
  check_address((void*)file);  //if argument is pointer
  
  bool result = filesys_remove(file);

  return result;
}
