/* $Id$
 *
 * Drop in replacement for writev(2)
 *
 * Copyright (C) 2009 - Gernot Tenchio
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

/*
 * This is only roughly tested since all systems I'm aware of have
 * writev(2)
 */

#include "writev.h"

#ifndef HAVE_WRITEV

#include <string.h>
#include <unistd.h>
#include <errno.h>

#define IOV_BUFSIZE 1500

#ifndef IOV_MAX
#define IOV_MAX 1024
#endif

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
  char buf[IOV_BUFSIZE];
  ssize_t total = 0, size = 0, n;
  int w = 0;

  if (iovcnt < 0 || iovcnt >= IOV_MAX) {
    errno = EINVAL;
    return -1;
  }

  while (w < iovcnt) {

    /* should we check this before writing any data? */
    if ((total + iov[w].iov_len) < total) {
      errno = EINVAL;
      return -1;
    }

    if (iov[w].iov_len >= IOV_BUFSIZE) {
      /* 
       * buffer is to small to hold the supplied string,
       * so we write it directly
       */
      if ((n = write(fd, iov[w].iov_base, iov[w].iov_len)) != iov[w].iov_len)
	return -1;
      total += n;
      w++;
    } else if (iov[w].iov_len + size > IOV_BUFSIZE) {
      /*
       * buffer has not enough space left to hold the supplied
       * string, write the buffer and reset its size
       */
      if ((n = write(fd, buf, size)) != size)
	return -1;
      total += n;
      size = 0;
    } else {
      /*
       * copy the supplied string to our buffer and adjust its
       * size
       */
      memcpy(buf + size, iov[w].iov_base, iov[w].iov_len);
      size += iov[w].iov_len;
      w++;
    }
  }
  if (size && (n = write(fd, buf, size)) != size)
    return -1;
  total += n;
  return total;
}

#ifdef WRITEV_TEST
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv, char **envp)
{
  struct iovec iovec[argc];
  int i;

  for (i = 0; i < argc; i++) {
    iovec[i].iov_len = strlen(argv[i]);
    iovec[i].iov_base = argv[i];
  }
  if (writev(2, iovec, i) == -1)
    return (EXIT_FAILURE);

  return (EXIT_SUCCESS);
}
#endif

#endif
