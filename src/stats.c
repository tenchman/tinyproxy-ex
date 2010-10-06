/* $Id$
 *
 * This module handles the statistics for tinyproxy-ex. There are only two
 * public API functions. The reason for the functions, rather than just a
 * external structure is that tinyproxy-ex is now multi-threaded and we can
 * not allow more than one child to access the statistics at the same
 * time. This is prevented by a mutex. If there is a need for more
 * statistics in the future, just add to the structure, enum (in the header),
 * and the switch statement in update_stats().
 *
 * Copyright (C) 2000  Robert James Kaes (rjkaes@flarenet.com)
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

#include "log.h"
#include "heap.h"
#include "htmlerror.h"
#include "stats.h"
#include "utils.h"

#define STAT_NUM_TYPE unsigned long int

struct stat_s {
  unsigned long int num_reqs;
  unsigned long int num_reqs_http;
  unsigned long int num_reqs_ftp;
  unsigned long int num_reqs_connect;
  unsigned long int num_badcons;
  unsigned long int num_open;
  unsigned long int num_refused;
  unsigned long int num_denied;
  unsigned long int num_ofcdmatch;
};

static struct stat_s *stats;

/*
 * Initialize the statistics information to zero.
 */
void init_stats(void)
{
  stats = malloc_shared_memory(sizeof(struct stat_s));
  if (stats == MAP_FAILED)
    return;

  memset(stats, 0, sizeof(struct stat));
}

int add_stat_variable(struct conn_s *connptr, char *key, STAT_NUM_TYPE value)
{
  char buf[128];
  snprintf(buf, sizeof(buf), "%lu", value);
  return add_error_variable(connptr, key, buf);
}

/*
 * Display the statics of the tinyproxy-ex server.
 */
int showstats(struct conn_s *connptr)
{
  static char *msg =
      "<html><head><title>%s (%s) stats</title></head>\r\n"
      "<body>\r\n"
      "<center><h2>%s (%s) run-time statistics</h2></center><hr>\r\n"
      "<blockquote>\r\n"
      "Number of open connections: %lu<br>\r\n"
      "Number of requests: %lu<br>\r\n"
      "Number of bad connections: %lu<br>\r\n"
      "Number of denied connections: %lu<br>\r\n"
      "Number of ofcd matched connections: %lu<br>\r\n"
      "Number of refused connections due to high load: %lu\r\n"
      "</blockquote>\r\n</body></html>\r\n";

  char *message_buffer;
  FILE *statfile;

  if (!config.statpage || (!(statfile = fopen(config.statpage, "r")))) {
    message_buffer = safemalloc(MAXBUFFSIZE);
    if (!message_buffer)
      return -1;

    snprintf(message_buffer, MAXBUFFSIZE, msg,
	     PACKAGE, VERSION, PACKAGE, VERSION,
	     stats->num_open,
	     stats->num_reqs,
	     stats->num_badcons, stats->num_denied, stats->num_ofcdmatch,
	     stats->num_refused);

    if (send_http_message(connptr, 200, "OK", message_buffer) < 0) {
      safefree(message_buffer);
      return -1;
    }

    safefree(message_buffer);
    return 0;
  }

  add_stat_variable(connptr, "opens", stats->num_open);
  add_stat_variable(connptr, "reqs", stats->num_reqs);
  add_stat_variable(connptr, "reqs_ftp", stats->num_reqs_ftp);
  add_stat_variable(connptr, "reqs_http", stats->num_reqs_http);
  add_stat_variable(connptr, "reqs_connect", stats->num_reqs_connect);
  add_stat_variable(connptr, "badconns", stats->num_badcons);
  add_stat_variable(connptr, "deniedconns", stats->num_denied);
  add_stat_variable(connptr, "ofcdmatch", stats->num_ofcdmatch);
  add_stat_variable(connptr, "refusedconns", stats->num_refused);

  add_standard_vars(connptr);
  send_http_headers(connptr, 200, "Statistic requested");
  send_html_file(statfile, connptr);
  fclose(statfile);

  return 0;
}

/*
 * Update the value of the statistics. The update_level is defined in
 * stats.h
 */
int update_stats(status_t update_level)
{
  switch (update_level) {
  case STAT_BADCONN:
    ++stats->num_badcons;
    break;
  case STAT_TYPE_FTP:
    ++stats->num_reqs_ftp;
    break;
  case STAT_TYPE_HTTP:
    ++stats->num_reqs_http;
    break;
  case STAT_TYPE_CONNECT:
    ++stats->num_reqs_connect;
    break;
  case STAT_OPEN:
    ++stats->num_open;
    ++stats->num_reqs;
    break;
  case STAT_CLOSE:
    --stats->num_open;
    break;
  case STAT_REFUSE:
    ++stats->num_refused;
    break;
  case STAT_DENIED:
    ++stats->num_denied;
    break;
  case STAT_OFCDMATCH:
    ++stats->num_ofcdmatch;
    ++stats->num_denied;
    break;
  default:
    return -1;
  }

  return 0;
}
