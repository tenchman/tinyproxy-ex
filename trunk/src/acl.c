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
#include "heap.h"
#include "log.h"
#include "sock.h"

/* linked list of acl definitions */
struct extacl_s {
  char *aclname;
  enum { ACL_NAME, ACL_NET } type;
  char *location, *rangeend;
  int netmask;
  struct extacl_s *next;
};
static struct extacl_s *extaccess_list;

/*
 * Take a netmask number (between 0 and 32) and returns a network ordered
 * value for comparison.
 */
static in_addr_t make_netmask(int netmask_num)
{
  assert(netmask_num >= 0 && netmask_num <= 32);

  return htonl(~((1 << (32 - netmask_num)) - 1));
}

/*
 * This function is called whenever a "string" access control is found in
 * the ACL.  From here we do both a text based string comparison, along with
 * a reverse name lookup comparison of the IP addresses.
 *
 * Return: 0 if host is denied
 *         1 if host is allowed
 *        -1 if no tests match, so skip
 */
#if 0
static inline int
acl_string_processing(struct acl_s *aclptr,
		      const char *ip_address, const char *string_address)
{
  int i;
  struct hostent *result;
  size_t test_length, match_length;

  /*
   * If the first character of the ACL string is a period, we need to
   * do a string based test only; otherwise, we can do a reverse
   * lookup test as well.
   */
  if (aclptr->location[0] != '.') {
    /* It is not a partial domain, so do a reverse lookup. */
    result = gethostbyname(aclptr->location);
    if (!result)
      goto STRING_TEST;

    for (i = 0; result->h_addr_list[i]; ++i) {
      if (strcmp(ip_address,
		 inet_ntoa(*((struct in_addr *) result->h_addr_list[i]))) ==
	  0) {
	/* We have a match */
	if (aclptr->acl_access == ACL_DENY) {
	  return 0;
	} else {
	  DEBUG2("Matched using reverse domain lookup: %s", ip_address);
	  return 1;
	}
      }
    }

    /*
     * If we got this far, the reverse didn't match, so drop down
     * to a standard string test.
     */
  }

STRING_TEST:
  test_length = strlen(string_address);
  match_length = strlen(aclptr->location);

  /*
   * If the string length is shorter than AC string, return a -1 so
   * that the "driver" will skip onto the next control in the list.
   */
  if (test_length < match_length)
    return -1;

  if (strcasecmp
      (string_address + (test_length - match_length), aclptr->location) == 0) {
    if (aclptr->acl_access == ACL_DENY)
      return 0;
    else
      return 1;
  }

  /* Indicate that no tests succeeded, so skip to next control. */
  return -1;
}
#endif

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
  new_acl_ptr = safemalloc(sizeof(struct extacl_s));
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
      if (!(new_acl_ptr->rangeend = safestrdup(nptr)))
	goto ERROROUT;
    } else {
      new_acl_ptr->netmask = 32;
    }
  } else {
    DEBUG2("ACL [%s] %d \"%s\" is a string.", aclname, acltype, location);

    new_acl_ptr->type = ACL_NAME;
    new_acl_ptr->netmask = 32;
  }

  if (!(new_acl_ptr->aclname = safestrdup(aclname)))
    goto ERROROUT;

  if (!(new_acl_ptr->location = safestrdup(location)))
    goto ERROROUT;

  *rev_acl_ptr = new_acl_ptr;
  new_acl_ptr->next = acl_ptr;

  return 0;

ERROROUT:
  if (new_acl_ptr->aclname)
    safefree(new_acl_ptr->aclname);
  if (new_acl_ptr->rangeend)
    safefree(new_acl_ptr->rangeend);
  safefree(new_acl_ptr);
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
find_extacl(int fd, const char *ip_address, const char *string_address,
	    char **aclname)
{
  struct extacl_s *aclptr;

  assert(fd >= 0);
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

      if (aclptr->rangeend && check_netrange(ip_address, aclptr))
	break;
      else if (check_netaddr(ip_address, aclptr))
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
    *aclname = safestrdup(aclptr->aclname);
    return FILTER_ALLOW;
  }
  *aclname = NULL;
  return config.default_policy;
}
