/* $Id$
 *
 * Create and free the connection structure. One day there could be
 * other connection related tasks put here, but for now the header
 * file and this file are only used for create/free functions and the
 * connection structure definition.
 *
 * Copyright (C) 2001  Robert James Kaes (rjkaes@flarenet.com)
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

#include "buffer.h"
#include "conns.h"
#include "log.h"
#include "stats.h"
#include "network.h"

struct conn_s *initialize_conn(int client_fd, const char *ipaddr,
			       const char *string_addr)
{
  struct conn_s *connptr;
  struct buffer_s *cbuffer, *sbuffer;

  assert(client_fd >= 0);

  /*
   * Allocate the memory for all the internal components
   */
  cbuffer = new_buffer();
  sbuffer = new_buffer();

  if (!cbuffer || !sbuffer)
    goto error_exit;

  /*
   * Allocate the space for the conn_s structure itself.
   */
  connptr = calloc(1, sizeof(struct conn_s));
  if (!connptr)
    goto error_exit;

  connptr->client_fd = client_fd;
  connptr->server_fd = -1;
#ifdef FTP_SUPPORT
  connptr->server_cfd = -1;
  connptr->ftp_isdir = FALSE;
#endif
  connptr->cbuffer = cbuffer;
  connptr->sbuffer = sbuffer;

  /* These store any error strings */
  connptr->error_number = -1;

  connptr->method = METH_UNKNOWN;
  connptr->show_stats = FALSE;

  /* There is _no_ content length initially */
  connptr->server.content_length = connptr->client.content_length = -1;

  connptr->client_ip_addr = strdup(ipaddr);
  connptr->client_string_addr = strdup(string_addr);

  update_stats(STAT_OPEN);

  return connptr;

error_exit:
  /*
   * If we got here, there was a problem allocating memory
   */
  if (cbuffer)
    delete_buffer(cbuffer);
  if (sbuffer)
    delete_buffer(sbuffer);

  return NULL;
}

void destroy_conn(struct conn_s *connptr)
{
  assert(connptr != NULL);

  if (connptr->client_fd != -1) {
    /* flush all remaining data and close the client file descriptor */
    disable_tcp_cork(connptr->client_fd);
    if (close(connptr->client_fd) < 0)
      log_message(LOG_INFO, "Client (%d) close message: %s",
		  connptr->client_fd, strerror(errno));
  }

  if (connptr->server_fd != -1) {
    /* flush all remaining data and close the server file descriptor */
    disable_tcp_cork(connptr->server_fd);
    if (close(connptr->server_fd) < 0)
      log_message(LOG_INFO, "Server (%d) close message: %s",
		  connptr->server_fd, strerror(errno));
  }
#ifdef FTP_SUPPORT
  if (connptr->server_cfd != -1)
    if (close(connptr->server_cfd) < 0)
      log_message(LOG_INFO, "Server cmd (%d) close message: %s",
		  connptr->server_cfd, strerror(errno));
  if (connptr->ftp_basedir)
    free(connptr->ftp_basedir);
  if (connptr->ftp_path)
    free(connptr->ftp_path);
  if (connptr->ftp_greeting)
    free(connptr->ftp_greeting);
#endif
  if (connptr->cbuffer)
    delete_buffer(connptr->cbuffer);
  if (connptr->sbuffer)
    delete_buffer(connptr->sbuffer);

  if (connptr->request_line)
    free(connptr->request_line);

  if (connptr->error_variables) {
    int i;

    for (i = 0; i != connptr->error_variable_count; ++i) {
      free(connptr->error_variables[i]->error_key);
      free(connptr->error_variables[i]->error_val);
      free(connptr->error_variables[i]);
    }

    free(connptr->error_variables);
  }

  if (connptr->error_string)
    free(connptr->error_string);

  if (connptr->client_ip_addr)
    free(connptr->client_ip_addr);
  if (connptr->client_string_addr)
    free(connptr->client_string_addr);

  free(connptr);

  update_stats(STAT_CLOSE);
}
