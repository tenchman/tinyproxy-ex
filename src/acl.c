/* $Id$
 *
 * This system handles Access Control for use of this daemon. A list of
 * domains, or IP addresses (including IP blocks) are stored in a list
 * which is then used to compare incoming connections.
 *
 * Copyright (C) 2000,2002  Robert James Kaes (rjkaes@flarenet.com)
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

#include "acl.h"

#include "log.h"
#include "sock.h"

#ifdef FILTER_SUPPORT

/* linked list of acl definitions */
struct extacl_s {
  char *aclname;
  enum { ACL_NAME, ACL_NET } type;
  char *location, *rangeend;
  int netmask;
  struct extacl_s *next;
};
static struct extacl_s *extaccess_list = NULL;

/*
 * Take a netmask number (between 0 and 32) and returns a network ordered
 * value for comparison.
 */
static in_addr_t make_netmask(int netmask_num)
{
  assert(netmask_num >= 0 && netmask_num <= 32);

  return netmask_num ? htonl(~((1 << (32 - netmask_num)) - 1)) : 0;
}

/* Extended acl processing */
int insert_extacl(char *aclname, acl_type_t acltype, char *location)
{
  size_t i;
  struct extacl_s **rev_acl_ptr, *acl_ptr, *new_acl_ptr;
  char *nptr;

  assert(aclname != NULL);
  assert(location != NULL);

  /*
   * First check to see if the location is a string or numeric.
   */
  for (i = 0; location[i] != '\0'; i++) {
    /*
     * Numeric strings can not contain letters, so test on it.
     */
    if (isalpha((unsigned char) location[i])) {
      break;
    }
  }

  /*
   * Add a new ACL to the list.
   */
  rev_acl_ptr = &extaccess_list;
  acl_ptr = extaccess_list;
  while (acl_ptr) {
    rev_acl_ptr = &acl_ptr->next;
    acl_ptr = acl_ptr->next;
  }
  new_acl_ptr = calloc(1, sizeof(struct extacl_s));
  if (!new_acl_ptr) {
    return -1;
  }

  if (location[i] == '\0') {
    DEBUG2("ACL [%s] %d \"%s\" is a number.", aclname, acltype, location);

    /*
     * We did not break early, so this a numeric location.
     * Check for a netmask.
     */
    new_acl_ptr->type = ACL_NET;
    nptr = strchr(location, '/');
    if ((nptr = strchr(location, '/'))) {
      *nptr++ = '\0';

      new_acl_ptr->netmask = strtol(nptr, NULL, 10);
      if (new_acl_ptr->netmask < 0 || new_acl_ptr->netmask > 32) {
	goto ERROROUT;
      }
      /*
       * Check for a ipaddress range */
    } else if ((nptr = strchr(location, '-'))) {
      *nptr++ = '\0';
      new_acl_ptr->rangeend = nptr;
    } else {
      new_acl_ptr->netmask = 32;
    }
  } else {
    DEBUG2("ACL [%s] %d \"%s\" is a string.", aclname, acltype, location);

    new_acl_ptr->type = ACL_NAME;
    new_acl_ptr->netmask = 32;
  }

  new_acl_ptr->aclname = aclname;
  new_acl_ptr->location = location;

  *rev_acl_ptr = new_acl_ptr;
  new_acl_ptr->next = acl_ptr;

  return 0;

ERROROUT:
  return -1;
}


static int check_netaddr(const char *ip_address, struct extacl_s *aclptr)
{
  struct in_addr test_addr, match_addr;
  in_addr_t netmask_addr;

  inet_aton(ip_address, &test_addr);
  inet_aton(aclptr->location, &match_addr);

  netmask_addr = make_netmask(aclptr->netmask);

  if ((test_addr.s_addr & netmask_addr) == (match_addr.s_addr & netmask_addr)) {
    return 1;
  }
  return 0;
}

static int check_netrange(const char *ip_address, struct extacl_s *aclptr)
{
  struct in_addr addr;
  uint32_t start, end, test;

  inet_aton(ip_address, &addr);
  test = htonl(addr.s_addr);
  inet_aton(aclptr->location, &addr);
  start = htonl(addr.s_addr);
  inet_aton(aclptr->rangeend, &addr);
  end = htonl(addr.s_addr);
  if ((test >= start && test <= end) || (test >= end && test <= start))
    return 1;
  return 0;
}

/*
 * Checks whether an acl is defined
 *
 * Returns:
 *     1 if further acl processing is required
 *     0/1 depending on config->default_policy
 */
int
find_extacl(const char *ip_address, const char *string_address, char **aclname)
{
  struct extacl_s *aclptr;

  assert(ip_address != NULL);
  assert(string_address != NULL);
  assert(aclname != NULL);

  /*
   * If there is no access list allow everything.
   */
  aclptr = extaccess_list;
  if (!aclptr)
    return FILTER_ALLOW;

  while (aclptr) {
    if (aclptr->type == ACL_NAME) {
      fprintf(stderr, "%s, string processing not yet implemented\n", __func__);
      aclptr = aclptr->next;
      continue;
    } else {			/* ACL_NUMERIC */
      if (ip_address[0] == 0) {
	aclptr = aclptr->next;
	continue;
      }

      if (aclptr->rangeend) {
	if (check_netrange(ip_address, aclptr))
	  break;
      } else if (check_netaddr(ip_address, aclptr))
	break;
    }

    /*
     * Dropped through... go on to the next one.
     */
    aclptr = aclptr->next;
  }

  if (aclptr) {
    log_message(LOG_INFO, "%s: found acl \"%s:%s\" for connection from %s",
		__func__, aclptr->aclname, aclptr->location, ip_address);
    *aclname = strdup(aclptr->aclname);
    return FILTER_ALLOW;
  }
  *aclname = NULL;
  return config.default_policy;
}

#endif
