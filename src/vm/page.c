#include <string.h>
#include <stdbool.h>
#include "filesys/file.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/page.h"

static unsigned int vm_hash_func (const struct hash_elem *e, void *aux UNUSED);
static bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static void vm_destroy_func (struct hash_elem *e, void *aux UNUSED);


void vm_init (struct hash *vm)
{
  hash_init (vm, vm_hash_func, vm_less_func, NULL);
}

static unsigned int vm_hash_func (const struct hash_elem *e, void *aux UNUSED)
{
  struct vm_entry *entry = hash_entry (e, struct vm_entry, elem);
  unsigned int hash_index = hash_int ((int)entry->vaddr);

  return hash_index;
}

static bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct vm_entry *first_entry = hash_entry(a, struct vm_entry, elem);
  struct vm_entry *second_entry = hash_entry(b, struct vm_entry, elem);

  if (first_entry->vaddr < second_entry->vaddr)
      return true;
  else
      return false;
}

bool insert_vme (struct hash *vm, struct vm_entry *vme)
{
  if (hash_insert (vm, &vme->elem) == NULL)
      return true;
  else
      return false;
}

bool delete_vme (struct hash *vm, struct vm_entry *vme)
{
  hash_delete (vm, &vme->elem);
  return true;
}

struct vm_entry* find_vme (void *vaddr)
{
  struct vm_entry *entry = (struct vm_entry*) malloc (sizeof (struct vm_entry));
  struct hash_elem *e = hash_find (&thread_current()->vm, &entry->elem);

  entry->vaddr = pg_round_down(vaddr);
 
  free(entry);

  if (e == NULL)
      return NULL;
  else
      return hash_entry (e, struct vm_entry, elem);
}

void vm_destroy (struct hash *vm)
{
  hash_destroy (vm, vm_destroy_func);
}

static void vm_destroy_func (struct hash_elem *e, void *aux UNUSED)
{
  struct vm_entry *entry = hash_entry(e, struct vm_entry, elem);
  if (entry->is_loaded)
  {
    palloc_free_page(pagedir_get_page(thread_current()->pagedir, entry->vaddr));
    pagedir_clear_page(thread_current()->pagedir, entry->vaddr);
  }
  free (entry);
}

bool load_file (void *kaddr, struct vm_entry *entry)
{
  if (file_read_at (entry->file, kaddr, entry->read_bytes, entry->offset) != (off_t)entry->read_bytes)
  {
    return false;
  }  

  memset (kaddr + entry->read_bytes, 0, entry->zero_bytes);
  return true;
}
