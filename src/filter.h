/* $Id$
 *
 * See 'filter.c' for a detailed description.
 *
 * Copyright (c) 1999  George Talusan (gstalusan@uwaterloo.ca)
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

#ifndef _TINYPROXY_FILTER_H_
#define _TINYPROXY_FILTER_H_

#define DEFAULT_OFCD_SOCKET_PATH "/tmp/ofcdsock"

typedef enum { FL_NONE, FL_ALLOW, FL_DENY, FL_OFCD, FL_TIME } filtertype_t;

extern void filter_init(void);
extern void filter_destroy(void);
extern int filter_domain(const char *host, const char *aclname, char **status);

extern void filter_set_default_policy(filter_policy_t policy);
extern int add_new_filter(char *aclname, char *expression);
#endif
