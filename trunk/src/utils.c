/* $Id$
 *
 * Misc. routines which are used by the various functions to handle strings
 * and memory allocation and pretty much anything else we can think of. Also,
 * the load cutoff routine is in here. Could not think of a better place for
 * it, so it's in here.
 *
 * Copyright (C) 1998       Steven Young
 * Copyright (C) 1999,2001,2003 by
 *   Robert James Kaes (rjkaes@flarenet.com)
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
#include <limits.h>
#include <sys/mman.h>
#include "tinyproxy-ex.h"

#include "conns.h"
#include "heap.h"
#include "http_message.h"
#include "utils.h"

/*
 * Build the data for a complete HTTP & HTML message for the client.
 */
int
send_http_message(struct conn_s *connptr, int http_code,
		  const char *error_title, const char *message)
{
  static char *headers[] = {
    "Server: " PACKAGE "/" VERSION,
    "Content-type: text/html",
    "Connection: close"
  };

  http_message_t msg;

  msg = http_message_create(http_code, error_title);
  if (msg == NULL)
    return -1;

  http_message_add_headers(msg, headers, 3);
  http_message_set_body(msg, message, strlen(message));
  http_message_send(msg, connptr->client_fd);
  http_message_destroy(msg);

  return 0;
}

int serve_local_file(struct conn_s *connptr, const char *filename)
{
  static char *headers[3] = {
    "Server: " PACKAGE "/" VERSION,
    "Content-type: application/octet-stream",
    "Connection: close"
  };
  char path[PATH_MAX], *tmp, *body;
  http_message_t msg;
  struct stat st;
  int ret, fd;

  /* simply do not allow double dots and url encoded stuff */
  if (strstr(filename, "..") || strchr(filename, '%')) {
    send_http_message(connptr, 400, "Bad Request", "Bad Request");
    return -1;
  }

  if (snprintf(path, PATH_MAX, DATAROOTDIR "/%s", filename) >= PATH_MAX) {
    send_http_message(connptr, 414, "Request-URI Too Long",
		      "Request-URI Too Long!");
    return -1;
  }

  if (stat(path, &st) == -1) {
    send_http_message(connptr, 404, "Not Found",
		      "The ressource you requested was not found on this server!");
    return -1;
  }

  if (!S_ISREG(st.st_mode)) {
    send_http_message(connptr, 403, "Forbidden", "Not a regular file!");
    return -1;
  }

  if ((fd = open(path, O_RDONLY)) == -1) {
    send_http_message(connptr, 403, "Forbidden", "File is protected!");
    return -1;
  }

  if ((body = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0))
      == MAP_FAILED) {
    send_http_message(connptr, 403, "Forbidden", "File is protected!");
    return -1;
  }

  if ((msg = http_message_create(200, "OK")) == NULL)
    return -1;

  if (tmp = strrchr(filename, '.')) {
    if (strcasecmp(tmp, ".css") == 0)
      headers[1] = "Content-type: text/css";
    else if (strcasecmp(tmp, ".html") == 0)
      headers[1] = "Content-type: text/html";
    else if (strcasecmp(tmp, ".png") == 0)
      headers[1] = "Content-type: image/png";
    else if (strcasecmp(tmp, ".jpg") == 0)
      headers[1] = "Content-type: image/jpg";
  }

  http_message_add_headers(msg, headers, 3);
  http_message_set_body(msg, body, st.st_size);
  ret = http_message_send(msg, connptr->client_fd);
  http_message_destroy(msg);

  munmap(body, st.st_size);

  return ret;
}


/*
 * Safely creates filename and returns the low-level file descriptor.
 */
int create_file_safely(const char *filename, unsigned int truncate_file)
{
  struct stat lstatinfo;
  int fildes;

  /*
   * lstat() the file. If it doesn't exist, create it with O_EXCL.
   * If it does exist, open it for writing and perform the fstat()
   * check.
   */
  if (lstat(filename, &lstatinfo) < 0) {
    /*
     * If lstat() failed for any reason other than "file not
     * existing", exit.
     */
    if (errno != ENOENT) {
      fprintf(stderr,
	      "%s: Error checking file %s: %s\n",
	      PACKAGE, filename, strerror(errno));
      return -EACCES;
    }

    /*
     * The file doesn't exist, so create it with O_EXCL to make
     * sure an attacker can't slip in a file between the lstat()
     * and open()
     */
    if ((fildes = open(filename, O_RDWR | O_CREAT | O_EXCL, 0600)) < 0) {
      fprintf(stderr,
	      "%s: Could not create file %s: %s\n",
	      PACKAGE, filename, strerror(errno));
      return fildes;
    }
  } else {
    struct stat fstatinfo;
    int flags;

    flags = O_RDWR;
    if (!truncate_file)
      flags |= O_APPEND;

    /*
     * Open an existing file.
     */
    if ((fildes = open(filename, flags)) < 0) {
      fprintf(stderr,
	      "%s: Could not open file %s: %s\n",
	      PACKAGE, filename, strerror(errno));
      return fildes;
    }

    /*
     * fstat() the opened file and check that the file mode bits,
     * inode, and device match.
     */
    if (fstat(fildes, &fstatinfo) < 0
	|| lstatinfo.st_mode != fstatinfo.st_mode
	|| lstatinfo.st_ino != fstatinfo.st_ino
	|| lstatinfo.st_dev != fstatinfo.st_dev) {
      fprintf(stderr,
	      "%s: The file %s has been changed before it could be opened\n",
	      PACKAGE, filename);
      close(fildes);
      return -EIO;
    }

    /*
     * If the above check was passed, we know that the lstat()
     * and fstat() were done on the same file. Now we check that
     * there's only one link, and that it's a normal file (this
     * isn't strictly necessary because the fstat() vs lstat()
     * st_mode check would also find this)
     */
    if (fstatinfo.st_nlink > 1 || !S_ISREG(lstatinfo.st_mode)) {
      fprintf(stderr,
	      "%s: The file %s has too many links, or is not a regular file: %s\n",
	      PACKAGE, filename, strerror(errno));
      close(fildes);
      return -EMLINK;
    }

    /*
     * Just return the file descriptor if we _don't_ want the file
     * truncated.
     */
    if (!truncate_file)
      return fildes;

    /*
     * On systems which don't support ftruncate() the best we can
     * do is to close the file and reopen it in create mode, which
     * unfortunately leads to a race condition, however "systems
     * which don't support ftruncate()" is pretty much SCO only,
     * and if you're using that you deserve what you get.
     * ("Little sympathy has been extended")
     */
#ifdef HAVE_FTRUNCATE
    ftruncate(fildes, 0);
#else
    close(fildes);
    if ((fildes = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0600)) < 0) {
      fprintf(stderr,
	      "%s: Could not open file %s: %s.",
	      PACKAGE, filename, strerror(errno));
      return fildes;
    }
#endif				/* HAVE_FTRUNCATE */
  }

  return fildes;
}

/*
 * Write the PID of the program to the specified file.
 */
int pidfile_create(const char *filename)
{
  int fildes;
  FILE *fd;

  /*
   * Create a new file
   */
  if ((fildes = create_file_safely(filename, TRUE)) < 0)
    return fildes;

  /*
   * Open a stdio file over the low-level one.
   */
  if ((fd = fdopen(fildes, "w")) == NULL) {
    fprintf(stderr,
	    "%s: Could not write PID file %s: %s.",
	    PACKAGE, filename, strerror(errno));
    close(fildes);
    unlink(filename);
    return -EIO;
  }

  fprintf(fd, "%ld\n", (long) getpid());
  fclose(fd);
  return 0;
}
