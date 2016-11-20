#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"


void
swap_init (void)
{
  struct block *swap_block = block_get_role (BLOCK_SWAP);
  lock_init (&swap_lock);
  swap_bitmap = bitmap_create (block_size(swap_block) / (PGSIZE / BLOCK_SECTOR_SIZE));  
}

void
swap_in (size_t used_index, void *kaddr)
{
  struct block *swap_block;
  swap_block = block_get_role (BLOCK_SWAP);

  if (!swap_block || !swap_bitmap)
    return;

  lock_acquire (&swap_lock);

  if (pg_ofs (kaddr) != 0)
    return;

  if (bitmap_test (swap_bitmap, used_index) != 0)
  {
    int i;
    for (i = 0; i < PGSIZE / BLOCK_SECTOR_SIZE; i++)
    {
      block_read (swap_block, used_index * PGSIZE / BLOCK_SECTOR_SIZE + i, (uint8_t*)kaddr + i * BLOCK_SECTOR_SIZE);
    }
    
    bitmap_flip (swap_bitmap, used_index);
  }
  
  lock_release (&swap_lock);
}

size_t
swap_out (void *kaddr)
{
  struct block *swap_block;
  swap_block = block_get_role (BLOCK_SWAP);
  
  if (swap_block == NULL || swap_bitmap == NULL)
  {
    NOT_REACHED();
  }
  
  lock_acquire (&swap_lock);

  size_t free_bitmap = bitmap_scan_and_flip (swap_bitmap, 0, 1, 0);  //Find available bit, and set it free

  int i;
  
  for (i = 0; i < PGSIZE / BLOCK_SECTOR_SIZE; i++)
    block_write (swap_block, free_bitmap * PGSIZE / BLOCK_SECTOR_SIZE + i, (uint8_t*) kaddr + i * BLOCK_SECTOR_SIZE);

  lock_release (&swap_lock);

  return free_bitmap;
}
