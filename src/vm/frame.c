#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

void
lru_list_init (void)
{
  list_init (&lru_list);  //Initialize lru list

  lock_init (&lru_list_lock);  //Initialize lru list lock

  lru_clock = NULL;
}

void
add_page_to_lru_list (struct page *page)
{
  lock_acquire (&lru_list_lock);  //Set lock
 
  list_push_back (&lru_list, &page->lru);  //push back page into end of lru list

  lock_release (&lru_list_lock);  //Unlock
}

void
del_page_from_lru_list (struct page *page)
{
  list_remove (&page->lru);  //Remove page from lru list
}

struct page*
alloc_page (enum palloc_flags flags)
{
  void *kaddr = palloc_get_page (flags);

  /*If kaddr is null try to get free page until get page*/
  while (kaddr == NULL)
  {
    lock_acquire (&lru_list_lock);  //Set lock

    kaddr = try_to_free_pages (flags);

    lock_release (&lru_list_lock);  //Unlock
  }

  struct page *page = (struct page*) malloc (sizeof(struct page));

  /*If fail to allocate, return null*/
  if (!page)
    return NULL;

  /*Initialize values*/
  page->kaddr = kaddr;
  page->thread = thread_current();
  page->vme = NULL;
  
  //printf ("page->kaddr  = %x\n", kaddr);
  add_page_to_lru_list (page);

  return page;
}

void
free_page (void *kaddr)
{
  struct list_elem *e;

  for (e = list_begin (&lru_list); e != list_end (&lru_list); e = list_next (e))
  {
    struct page *page = list_entry (e, struct page, lru);

    /*If addr of page is kaddr then free and end loop*/
    if (page->kaddr == kaddr)
    {
      __free_page (page);
      break;
    }
  }
}

void
__free_page (struct page *page)
{
  lock_acquire (&lru_list_lock);  //Set lock

  del_page_from_lru_list (page);  //Remove page form list
  
  lock_release (&lru_list_lock);  //Unlock

  palloc_free_page (page->kaddr);

  free(page);
}

struct list_elem*
get_next_lru_clock (void)
{
  if (lru_clock == NULL)
    return NULL;

  if (list_size (&lru_list) == 1)  //If list has only 1
    return NULL;

  if (list_next (lru_clock) == list_end (&lru_list))  //If element is end of list return begin element
    return list_begin (&lru_list);

  return list_next (lru_clock);  //Return next element
}

void*
try_to_free_pages (enum palloc_flags flags)
{
  if (list_empty(&lru_list))
  {
    lru_clock = NULL;
    return NULL;
  }

  if (!lru_clock)
    lru_clock = list_begin (&lru_list);

  while (lru_clock)
  {
    struct list_elem *next = get_next_lru_clock();
    struct page *page = list_entry (lru_clock, struct page, lru);

    lru_clock = next;

    struct thread *t = page->thread;

    //printf ("vaddr = %x\n", page->vme->vaddr);
    if (pagedir_is_accessed (t->pagedir, page->vme->vaddr))
    {
      pagedir_set_accessed (t->pagedir, page->vme->vaddr, false);
    }
    else
    {
      if (pagedir_is_dirty (t->pagedir, page->vme->vaddr) || page->vme->type == VM_ANON)
      {
        if (page->vme->type == VM_FILE)
        {
          lock_acquire (&filesys_lock);  //Set filesys lock to write

          file_write_at (page->vme->file, page->kaddr, page->vme->read_bytes, page->vme->offset);

          lock_release (&filesys_lock);  //Unlock
        }
        else if (page->vme->type != VM_BIN)//If vme is dirty VM_BIN or VM_ANON
        {
          page->vme->type = VM_ANON;
          page->vme->swap_slot = swap_out (page->kaddr);
        }
      }
      page->vme->is_loaded = false;  //In swap partition

      del_page_from_lru_list(page);  //Remove from memory
      
      pagedir_clear_page (t->pagedir, page->vme->vaddr);
      palloc_free_page (page->kaddr);
      free (page);
      
      return palloc_get_page (flags);
    }
  }
  
  return NULL;
}

void free_all_pages (tid_t tid) {
  struct list_elem *elem, *tmp;
  struct page *page;
  for (elem = list_begin(&lru_list); elem != list_end (&lru_list);)
  {
    tmp = list_next (elem);
    page = list_entry (elem, struct page, lru);
    if (page->thread->tid == tid)
    {
      del_page_from_lru_list (page);
    }
    elem = tmp;
  }
}
