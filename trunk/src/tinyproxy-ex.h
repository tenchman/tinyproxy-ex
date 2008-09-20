/* $Id$
 *
 * See 'tinyproxy-ex.c' for a detailed description.
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

#ifndef TINYPROXY_TINYPROXY_H
#define TINYPROXY_TINYPROXY_H

#include "common.h"

/* Global variables for the main controls of the program */
#define MAXBUFFSIZE	((size_t)(1024 * 96))	/* Max size of buffer */
#define MAX_IDLE_TIME 	(60 * 10)	/* 10 minutes of no activity */

/* Name to serve local request on */
#define INTERNALNAME  "tinyproxy-ex.intern"
/*
 * Even if upstream support is not compiled into tinyproxy-ex, this
 * structure still needs to be defined.
 */

#define FTP_SUPPORT 1

typedef enum {
  FILTER_ALLOW,
  FILTER_DENY,
} filter_policy_t;

struct upstream {
  struct upstream *next;
  char *domain;			/* optional */
  char *host;
  char *authentication;
  int port;
  in_addr_t ip, mask;
};

#define USE

struct config_s {
  char *logf_name;
  char *config_file;
  unsigned int syslog:1;
  unsigned int quit:1;
  unsigned reverselookup:1;
  int port;
  int connecttimeout;
  int connectretries;
  char *stathost;
  char *username;
  char *group;
  char *ipAddr;
#ifdef FILTER_ENABLE
  /* path to the ofcd unix domain socket */
  char *ofcdsocket;
  /* path to a file containing the ofcd category descriptions */
  char *ofcdcategories;
  struct filter_s {
    char *expression;
    char *aclname;
  } **filters;
  unsigned filter:1;
  unsigned filter_url:1;
  unsigned filter_extended:1;
  unsigned filter_casesensitive:1;
  filter_policy_t default_policy;
#endif				/* FILTER_ENABLE */
#ifdef XTINYPROXY_ENABLE
  char *my_domain;
#endif
#ifdef UPSTREAM_SUPPORT
  struct upstream *upstream_list;
#endif				/* UPSTREAM_SUPPORT */
  char *pidpath;
  unsigned int idletimeout;
  char *bind_address;

  /*
   * The configured name to use in the HTTP "Via" header field.
   */
  char *via_proxy_name;

  /* 
   * Error page support.  This is an array of pointers to structures
   * which describe the error page path, and what HTTP error it handles.
   * an example would be { "/usr/local/etc/tinyproxy-ex/404.html", 404 }
   * Ending of array is noted with NULL, 0.
   */
  struct error_pages_s {
    char *errorpage_path;
    unsigned int errorpage_errnum;
  } **errorpages;
  /* 
   * Error page to be displayed if appropriate page cannot be located
   * in the errorpages structure.
   */
  char *errorpage_undef;

  /* 
   * The HTML statistics page. 
   */
  char *statpage;
};

/* Global Structures used in the program */
extern struct config_s config;
extern unsigned int received_sighup;	/* boolean */
extern unsigned int processed_config_file;	/* boolean */

#endif
