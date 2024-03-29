/* $Id$
 *
 * The functions found here are used for communicating across a
 * network.  They include both safe reading and writing (which are
 * the basic building blocks) along with two functions for
 * easily reading a line of text from the network, and a function
 * to write an arbitrary amount of data to the network.
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


#include "network.h"
#include "log.h"

#ifdef TCP_CORK
void enable_tcp_cork(int fd)
{
  int state = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));
}

void disable_tcp_cork(int fd)
{
  int state = 0;
  setsockopt(fd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));
}
#endif

/*
 * Write the buffer to the socket. If an EINTR occurs, pick up and try
 * again. Keep sending until the buffer has been sent.
 */
ssize_t safe_send(int fd, const char *buffer, size_t count)
{
  ssize_t len, bytestosend = (ssize_t) count;

  assert(fd >= 0);
  assert(buffer != NULL);
  assert(bytestosend > 0);

  while (1) {
    len = send(fd, buffer, bytestosend, MSG_NOSIGNAL);

    if (len < 0) {
      if (errno == EINTR)
	continue;
      else
	return -errno;
    }

    if (len == bytestosend)
      break;

    buffer += len;
    bytestosend -= len;
  }

  return count;
}

/*
 * Matched pair for safe_send(). If an EINTR occurs, pick up and try
 * again.
 */
ssize_t safe_recv(int fd, char *buffer, size_t count)
{
  ssize_t len;

  do {
    len = recv(fd, buffer, count, 0);
  } while (len < 0 && errno == EINTR);

  return len;
}

/*
 * Send a "message" to the file descriptor provided. This handles the
 * differences between the various implementations of vsnprintf. This code
 * was basically stolen from the snprintf() man page of Debian Linux
 * (although I did fix a memory leak. :)
 *
 * Return the bytes written to the file descriptor or -1 in case of an error.
 */
int send_message(int fd, const char *fmt, ...)
{
  ssize_t n;
  ssize_t size = (1024 * 8);	/* start with 8 KB and go from there */
  char *buf, *tmpbuf;
  va_list ap;

  if ((buf = malloc(size)) == NULL)
    return -1;

  while (1) {
    va_start(ap, fmt);
    n = vsnprintf(buf, size, fmt, ap);
    va_end(ap);

    /* If that worked, break out so we can send the buffer */
    if (n > -1 && n < size)
      break;

    /* Else, try again with more space */
    if (n > -1)
      /* precisely what is needed (glibc2.1) */
      size = n + 1;
    else
      /* twice the old size (glibc2.0) */
      size *= 2;

    if ((tmpbuf = realloc(buf, size)) == NULL) {
      free(buf);
      return -1;
    } else
      buf = tmpbuf;
  }

  n = safe_send(fd, buf, n);
  free(buf);
  return n;
}

/*
 * Read in a "line" from the socket. It might take a few loops through
 * the read sequence. The full string is allocate off the heap and stored
 * at the whole_buffer pointer. The caller needs to free the memory when
 * it is no longer in use. The returned line is NULL terminated.
 *
 * Returns the length of the buffer on success (not including the NULL
 * termination), 0 if the socket was closed, and -1 on all other errors.
 */
#define SEGMENT_LEN (512)
#define MAXIMUM_BUFFER_LENGTH (128 * 1024)
ssize_t recvline(int fd, char **whole_buffer)
{
  ssize_t whole_buffer_len;
  char buffer[SEGMENT_LEN];
  char *ptr;
  time_t starttime;

  ssize_t ret;
  ssize_t diff;

  struct read_lines_s {
    char *data;
    size_t len;
    struct read_lines_s *next;
  };
  struct read_lines_s *first_line, *line_ptr;

  first_line = calloc(sizeof(struct read_lines_s), 1);
  if (!first_line)
    return -ENOMEM;

  line_ptr = first_line;

  whole_buffer_len = 0;
  for (;;) {

    starttime = time(NULL);
    while ((ret = recv(fd, buffer, SEGMENT_LEN, MSG_PEEK | MSG_DONTWAIT)) < 0
	   && errno == EAGAIN) {

      if ((long) (time(NULL) - starttime) > (long) config.idletimeout) {
	log_message(LOG_INFO,
		    "Idle Timeout in recvline %u.", config.idletimeout);
	goto CLEANUP;
      }
      usleep(200000);
    }

    if (ret <= 0)
      goto CLEANUP;

    ptr = memchr(buffer, '\n', ret);
    if (ptr)
      diff = ptr - buffer + 1;
    else
      diff = ret;

    whole_buffer_len += diff;

    /*
     * Don't allow the buffer to grow without bound. If we
     * get to more than MAXIMUM_BUFFER_LENGTH close.
     */
    if (whole_buffer_len > MAXIMUM_BUFFER_LENGTH) {
      ret = -ERANGE;
      goto CLEANUP;
    }

    line_ptr->data = malloc(diff);
    if (!line_ptr->data) {
      ret = -ENOMEM;
      goto CLEANUP;
    }

    ret = recv(fd, line_ptr->data, diff, 0);
    /* to be safe */
    if (ret <= 0)
      goto CLEANUP;

    line_ptr->len = diff;

    if (ptr) {
      line_ptr->next = NULL;
      break;
    }

    line_ptr->next = calloc(sizeof(struct read_lines_s), 1);
    if (!line_ptr->next) {
      ret = -ENOMEM;
      goto CLEANUP;
    }
    line_ptr = line_ptr->next;
  }

  *whole_buffer = malloc(whole_buffer_len + 1);
  if (!*whole_buffer) {
    ret = -ENOMEM;
    goto CLEANUP;
  }

  *(*whole_buffer + whole_buffer_len) = '\0';

  whole_buffer_len = 0;
  line_ptr = first_line;
  while (line_ptr) {
    memcpy(*whole_buffer + whole_buffer_len, line_ptr->data, line_ptr->len);
    whole_buffer_len += line_ptr->len;

    line_ptr = line_ptr->next;
  }

  ret = whole_buffer_len;

CLEANUP:
  do {
    line_ptr = first_line->next;
    if (first_line->data)
      free(first_line->data);
    free(first_line);
    first_line = line_ptr;
  } while (first_line);

  return ret;
}
