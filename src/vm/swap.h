#ifndef SWAP_H
#define SWAP_H

#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include <bitmap.h>

struct lock swap_lock;
struct bitmap *swap_bitmap;

void swap_init (void);
void swap_in (size_t used_index, void *kaddr);
size_t swap_out (void *kaddr);

#endif
