/* $Id$
 *
 * See 'heap.c' for a detailed description.
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

#ifndef TINYPROXY_HEAP_H
#define TINYPROXY_HEAP_H

/*
 * Allocate memory from the "shared" region of memory.
 */
extern void *malloc_shared_memory(size_t size);
extern void *calloc_shared_memory(size_t nmemb, size_t size);

#endif
