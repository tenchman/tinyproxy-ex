/* $Id$
 *
 * Debugging versions of various heap related functions are combined
 * here.  The debugging versions include assertions and also print
 * (to standard error) the function called along with the amount
 * of memory allocated, and where the memory is pointing.  The
 * format of the log message is standardized.
 *
 * Copyright (C) 2002  Robert James Kaes (rjkaes@flarenet.com)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include "tinyproxy-ex.h"
#include "heap.h"
#include "text.h"

/*
 * Allocate a block of memory in the "shared" memory region.
 *
 * FIXME: This uses the most basic (and slowest) means of creating a
 * shared memory location.  It requires the use of a temporary file.  We might
 * want to look into something like MM (Shared Memory Library) for a better
 * solution.
 */
void *malloc_shared_memory(size_t size)
{
  int fd;
  void *ptr;
  char buffer[32];

  static char *shared_file = "/tmp/tinyproxy-ex.shared.XXXXXX";

  assert(size > 0);

  strlcpy(buffer, shared_file, sizeof(buffer));

  if ((fd = mkstemp(buffer)) == -1)
    return (void *) MAP_FAILED;
  unlink(buffer);

  if (ftruncate(fd, size) == -1)
    return (void *) MAP_FAILED;
  ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

  return ptr;
}

/*
 * Allocate a block of memory from the "shared" region an initialize it to
 * zero.
 */
void *calloc_shared_memory(size_t nmemb, size_t size)
{
  void *ptr;
  long length;

  assert(nmemb > 0);
  assert(size > 0);

  length = nmemb * size;

  ptr = malloc_shared_memory(length);
  if (ptr == MAP_FAILED)
    return ptr;

  memset(ptr, 0, length);

  return ptr;
}
