/* $Id$
 *
 * Logs the various messages which tinyproxy-ex produces to either a log file or
 * the syslog daemon. Not much to it...
 *
 * Copyright (C) 1998  Steven Young
 * Copyright (C) 1999  Robert James Kaes (rjkaes@flarenet.com)
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
#include "log.h"
#include "utils.h"
#include "vector.h"

static char *syslog_level[] = {
  NULL,
  NULL,
  "CRITICAL",
  "ERROR",
  "WARNING",
  "NOTICE",
  "INFO",
  "DEBUG",
  "CONNECT"
};

#define TIME_LENGTH 16
#define STRING_LENGTH 800
#define PREFIX_LENGTH TIME_LENGTH + 64

/*
 * Global file descriptor for the log file
 */
int log_file_fd = -1;
int access_log_fd = -1;

/*
 * Store the log level setting.
 */
static int log_level = LOG_INFO;

/*
 * Hold a listing of log messages which need to be sent once the log
 * file has been established.
 * The key is the actual messages (already filled in full), and the value
 * is the log level.
 */
static vector_t log_message_storage;

/*
 * Open the log file and store the file descriptor in a global location.
 */
int open_log_file(const char *log_file_name)
{
  log_file_fd = create_file_safely(log_file_name, FALSE);
  return log_file_fd;
}

/*
 * Close the log file
 */
void close_log_file(void)
{
  close(log_file_fd);
}

/*
 * Truncate log file to a zero length.
 */
int truncate_log_file(void)
{
  lseek(log_file_fd, 0, SEEK_SET);
  return ftruncate(log_file_fd, 0);
}

/*
 * Set the log level for writing to the log file.
 */
void set_log_level(int level)
{
  log_level = level;
}

/*
 * This routine logs messages to either the log file or the syslog function.
 */
void log_message(int level, char *fmt, ...)
{
  va_list args;
  time_t nowtime;
  char str[STRING_LENGTH];

#ifdef NDEBUG
  /*
   * Figure out if we should write the message or not.
   */
  if (log_level == LOG_CONN) {
    if (level == LOG_INFO)
      return;
  } else if (log_level == LOG_INFO) {
    if (level > LOG_INFO && level != LOG_CONN)
      return;
  } else if (level > log_level)
    return;
#endif

#ifdef HAVE_SYSLOG_H
  if (config.syslog && level == LOG_CONN)
    level = LOG_INFO;
#endif

  va_start(args, fmt);

  /*
   * If the config file hasn't been processed, then we need to store
   * the messages for later processing.
   */
  if (!processed_config_file) {
    char *entry_buffer;

    if (!log_message_storage) {
      log_message_storage = vector_create();
      if (!log_message_storage)
	return;
    }

    vsnprintf(str, STRING_LENGTH, fmt, args);

    entry_buffer = safemalloc(strlen(str) + 6);
    if (!entry_buffer)
      return;

    sprintf(entry_buffer, "%d %s", level, str);
    vector_append(log_message_storage, entry_buffer, strlen(entry_buffer) + 1);

    safefree(entry_buffer);
    va_end(args);

    return;
  }
#ifdef HAVE_SYSLOG_H
  if (config.syslog) {
#  ifdef HAVE_VSYSLOG_H
    vsyslog(level, fmt, args);
#  else
    vsnprintf(str, STRING_LENGTH, fmt, args);
    syslog(level, "%s", str);
#  endif
  } else {
#endif
    char time_string[TIME_LENGTH];
    struct iovec iov[3];
    char pfx[PREFIX_LENGTH];
    int truncated = 0;

    assert(log_file_fd >= 0);

    nowtime = time(NULL);
    /* Format is month day hour:minute:second (24 time) */
    strftime(time_string, TIME_LENGTH, "%b %d %H:%M:%S", localtime(&nowtime));

    iov[0].iov_base = pfx;
    iov[0].iov_len =
	snprintf(pfx, PREFIX_LENGTH, "%-9s %s [%ld]: ", syslog_level[level],
		 time_string, (long int) getpid());
    iov[1].iov_base = str;
    iov[1].iov_len = vsnprintf(str, STRING_LENGTH, fmt, args);
    iov[2].iov_base = "\n";
    iov[2].iov_len = 1;
#ifdef HAVE_FTRUNCATE
    /* if writev() fails with ENOSPC or EFBIG, ftruncate() the logfile and
     * try again. If this fails too, bail out.
     */
  again:
    if (writev(log_file_fd, iov, 3) == -1) {
      if (!truncated && errno != ENOSPC && errno != EFBIG) {
	fprintf(stderr, "%s: Could not write to logfile: %s.", PACKAGE,
		strerror(errno));
	exit(EXIT_FAILURE);
      }
      if (ftruncate(log_file_fd, 0) == -1) {
	fprintf(stderr,
		"%s: Could not write to logfile, ftruncate() failed: %s.",
		PACKAGE, strerror(errno));
	exit(EXIT_FAILURE);
      }
      goto again;
    }
#else
    /* Without ftruncate() we simply bail out if writev() fails, sorry! */
    if (writev(log_file_fd, iov, 3) == -1) {
      fprintf(stderr, "%s: Could not write to logfile: %s.", PACKAGE,
	      strerror(errno));
      exit(EXIT_FAILURE);
    }
#endif

#ifdef HAVE_SYSLOG_H
  }
#endif

  va_end(args);
}

/*
 * This needs to send any stored log messages.
 */
void send_stored_logs(void)
{
  char *string;
  char *ptr;

  int level;

  int i;

  for (i = 0; i != vector_length(log_message_storage); ++i) {
    string = vector_getentry(log_message_storage, i, NULL);

    ptr = strchr(string, ' ') + 1;
    level = atoi(string);

#if NDEBUG
    if (log_level == LOG_CONN && level == LOG_INFO)
      continue;
    else if (log_level == LOG_INFO) {
      if (level > LOG_INFO && level != LOG_CONN)
	continue;
    } else if (level > log_level)
      continue;
#endif

    log_message(level, ptr);
  }

  vector_delete(log_message_storage);
  log_message_storage = NULL;
}
