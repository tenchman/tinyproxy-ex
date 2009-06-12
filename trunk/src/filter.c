/* $Id$
 *
 * Copyright (c) 1999  George Talusan (gstalusan@uwaterloo.ca)
 * Copyright (c) 2002  James E. Flemer (jflemer@acm.jhu.edu)
 * Copyright (c) 2002  Robert James Kaes (rjkaes@flarenet.com)
 *
 * A substring of the domain to be filtered goes into the file
 * pointed at by DEFAULT_FILTER.
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

#include "filter.h"
#include "heap.h"
#include "log.h"
#include "regexp.h"
#include "reqs.h"
#include <limits.h>

#define FILTER_BUFFER_LEN (512)
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

#define MAX_CATEGORIES 96

static int err;

struct filter_rulelist {
  struct filter_rulelist *next;
  int type;
  char *pat;
  regex_t *cpat;
} rules;

struct filter_list {
  struct filter_list *next;
  char *aclname;
  struct filter_rulelist *rules;
};

static struct filter_list *fl = NULL;
static int filterlist_initialized = 0;
static int catlist_initialized = 0;
static char *catlist[MAX_CATEGORIES];

static struct filter_list *filter_get(const char *aclname)
{
  struct filter_list *p = NULL;

  DEBUG2("%s: looking up filters for %s", __func__, aclname);
  if (fl)
    for (p = fl; p; p = p->next) {
      if (strcmp(p->aclname, aclname) == 0)
	break;
    }
  return p;
}

/*
  Example:
  filter allow localhost "/etc/tinyhost/filter"
*/
int add_new_filter(char *aclname, char *expression)
{
  static int filter_count = 1;

  /* First, add space for another pointer to the filter array. */
  config.filters =
      saferealloc(config.filters,
		  sizeof(struct filter_s *) * (filter_count + 1));
  if (!config.filters)
    return (-1);

  /* Allocate space for an actual structure */
  config.filters[filter_count - 1] = safemalloc(sizeof(struct filter_s));
  if (!config.filters[filter_count - 1])
    return (-1);

  log_message(LOG_INFO, "%s: New filter '%s' for %s", __func__, expression,
	      aclname);

  /* Set values for filters structure. */
  config.filters[filter_count - 1]->expression = safestrdup(expression);
  if (!config.filters[filter_count - 1]->expression)
    return (-1);

  config.filters[filter_count - 1]->aclname = safestrdup(aclname);
  if (!config.filters[filter_count - 1]->aclname)
    return (-1);


  /* Set NULL to denote end of array */
  config.filters[filter_count] = NULL;

  filter_count++;
  return (0);
}

/* add a rule to the filter rulelist
 *
 * return the pointer of the newly created rule on success,
 * NULL otherwise
 */
static struct filter_rulelist *filter_addrule(const char *pat,
					      struct filter_rulelist **list,
					      filtertype_t type)
{
  struct filter_rulelist *p = *list;

  log_message(LOG_INFO, "%s:    Adding pattern '%d' '%s'", __func__, type, pat);

  if (!p) {			/* head of list */
    p = *list = safecalloc(1, sizeof(struct filter_rulelist));
  } else {			/* next entry */

    /* 
     * find the end of our list, this leaves room for
     * optimizations
     */
    while (p->next)
      p = p->next;

    p->next = safecalloc(1, sizeof(struct filter_rulelist));
    p = p->next;
  }

  if (p) {
    p->type = type;
    if (!(p->pat = safestrdup(pat))) {
      safefree(p);
      p = NULL;
    }
  }
  return p;
}

/* gets called if the first ofcd rule is found */
static void filter_read_catlist(void)
{
  FILE *fd;
  char buf[FILTER_BUFFER_LEN];

  catlist_initialized = 1;

  if (!config.ofcdcategories) {
    log_message(LOG_INFO, "No category file specified");
    return;
  }

  if ((fd = fopen(config.ofcdcategories, "r"))) {
    int i = 0;
    while (i < MAX_CATEGORIES && fgets(buf, FILTER_BUFFER_LEN, fd)) {
      buf[strlen(buf) - 1] = '\0';
      if (!(catlist[i++] = safestrdup(buf))) {
	log_message(LOG_ERR, "%s: memory problem", __func__);
	goto COMMON_EXIT;
      }
    }
    catlist_initialized = 2;
    log_message(LOG_INFO, "Got %d categories from %s", i,
		config.ofcdcategories);
  } else
    log_message(LOG_INFO, "%s: Read failed %s: %m", __func__,
		config.ofcdcategories);

COMMON_EXIT:
  fclose(fd);
}

static filtertype_t filter_guesstype(const char *line, char **endptr)
{
  filtertype_t type = FL_NONE;

  assert(line != NULL);
  assert(endptr != NULL);

  if (strncmp(line, "allow ", 6) == 0) {
    *endptr = (char *) line + 6;
    type = FL_ALLOW;
  } else if (strncmp(line, "deny ", 5) == 0) {
    *endptr = (char *) line + 5;
    type = FL_DENY;
  } else if (strncmp(line, "ofcd ", 5) == 0) {
    *endptr = (char *) line + 5;
    type = FL_OFCD;
  }
  return type;
}

static void filter_read(const char *filename, struct filter_rulelist **list)
{
  FILE *fd;
  struct filter_rulelist *p;
  filtertype_t type;
  char buf[FILTER_BUFFER_LEN];
  char *s, *endptr;
  int cflags;

  log_message(LOG_INFO, "%s: Reading %s", __func__, filename);

  if ((fd = fopen(filename, "r"))) {

    cflags = REG_NEWLINE | REG_NOSUB;
    if (config.filter_extended)
      cflags |= REG_EXTENDED;
    if (!config.filter_casesensitive)
      cflags |= REG_ICASE;

    while (fgets(buf, FILTER_BUFFER_LEN, fd)) {

      type = filter_guesstype(buf, &endptr);
      if (type == FL_NONE)
	continue;

      /*
       * Remove any trailing white space and
       * comments.
       */
      s = endptr;
      while (*s) {
	if (isspace((unsigned char) *s))
	  break;
	if (*s == '#') {
	  /*
	   * If the '#' char is preceeded by
	   * an escape, it's not a comment
	   * string.
	   */
	  if (s == buf || *(s - 1) != '\\')
	    break;
	}
	++s;
      }
      *s = '\0';

      /* skip leading whitespace */
      s = endptr;
      while (*s && isspace((unsigned char) *s))
	s++;

      /* skip blank lines and comments */
      if (*s == '\0')
	continue;

      if (!(p = filter_addrule(s, list, type))) {
	fprintf(stderr, "Memory problem\n");
	exit(EX_DATAERR);
      }

      /* initialize the categories if needed */
      if (type == FL_OFCD) {
	if (!catlist_initialized)
	  filter_read_catlist();
      } else {
	/* precompile the regexes */
	p->cpat = safemalloc(sizeof(regex_t));

	if ((err = regcomp(p->cpat, p->pat, cflags)) != 0) {
	  fprintf(stderr, "Bad regex in %s: %s\n", filename, p->pat);
	  exit(EX_DATAERR);
	}
      }
    }
    if (ferror(fd)) {
      perror("fgets");
      exit(EX_DATAERR);
    }
    fclose(fd);

  } else
    log_message(LOG_INFO, "%s: Read failed %s: %m", __func__, filename);
}

/*
 * Initializes a linked list of strings containing hosts/urls to be filtered
 */
void filter_init(void)
{
  struct filter_list *p = NULL, *q;
  struct filter_s *f;

  if (!config.filters) {
    filterlist_initialized = 1;
    return;
  }

  if (!fl && !filterlist_initialized) {
    int i = 0;
    while ((f = config.filters[i++])) {

      /* are there already rules for this acl? */
      if (!(q = filter_get(f->aclname))) {

	log_message(LOG_INFO, "%s: New Filter for %s", __func__, f->aclname);

	if (!p) {		/* head of list */
	  p = fl = safecalloc(1, sizeof(struct filter_list));
	} else {		/* next entry */
	  p->next = safecalloc(1, sizeof(struct filter_list));
	  p = p->next;
	}
	p->aclname = safestrdup(f->aclname);
	q = p;
      } else {
	log_message(LOG_INFO, "%s: Found Filter for %s", __func__, f->aclname);
      }

      filter_read(f->expression, &q->rules);
    }
    filterlist_initialized = 1;
  }
}

/* unlink the list */
void filter_destroy(void)
{
  struct filter_list *p, *q;

  if (filterlist_initialized) {
    for (p = q = fl; p; p = q) {
      struct filter_rulelist *r, *s;
      for (r = s = p->rules; r; r = s) {
	if (r->cpat) {
	  regfree(r->cpat);
	  safefree(r->cpat);
	}
	safefree(r->pat);
	s = r->next;
	safefree(r);
      }
      safefree(p->aclname);
      q = p->next;
      safefree(p);
    }
    fl = NULL;
    filterlist_initialized = 0;
  }
}

/*
 * Set the default filtering policy
 */
void filter_set_default_policy(filter_policy_t policy)
{
  if (policy == FILTER_DENY)
    config.filter = 1;
  config.default_policy = policy;
}

int htoi(char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  else if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  else if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}


/*
 *  0 if matched, status will be filled with the categories
 *  1 no match
 * -1 error
 */

int filter_ofcd(const unsigned char *pat, const char *uri, char **status)
{
  struct iovec iov[2];
  struct sockaddr_un addr;
  int sockfd, len;
  int match = 1, outlen = 0;
  unsigned char buf[128];
  char outbuf[1024];
  char *ofcdsocket = config.ofcdsocket;

  if (!uri)
    return 1;

  if (!ofcdsocket)
    ofcdsocket = DEFAULT_OFCD_SOCKET_PATH;

  if ((sockfd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
    fprintf(stderr, "can't create socket\n");
    goto COMMON_ERROR;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_LOCAL;
  strncpy(addr.sun_path, ofcdsocket, UNIX_PATH_MAX);

  if (connect(sockfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
    fprintf(stderr, "Failed to connect to unix domain socket %s! %m\n",
	    addr.sun_path);
    goto COMMON_ERROR;
  }

  iov[0].iov_base = "MATCH ";
  iov[0].iov_len = 6;
  iov[1].iov_base = (char *) uri;
  iov[1].iov_len = strlen(uri);

  if (writev(sockfd, iov, 2) == -1) {
    fprintf(stderr, "Failed to writev() to socket! %m\n");
    goto COMMON_ERROR;
  }

  if ((len = read(sockfd, buf, sizeof(buf))) == -1) {
    fprintf(stderr, "Failed to read from socket! %m\n");
    goto COMMON_ERROR;
  }

  iov[0].iov_base = "QUIT";
  iov[0].iov_len = 4;
  if (writev(sockfd, iov, 1) == -1) {
    /* QUIT failed, ignore it for now */
    fprintf(stderr, "Failed to writev() to socket! %m\n");
  }

  buf[len] = (char) 0;
  close(sockfd);

  if (len != 32) {
    log_message(LOG_ERR, "unexpected answer from ofcd: %s", buf);
    return -1;
  }

  if (strcmp((char *) buf, "00000000FFFFFFFFFFFFFFFFFFFFFFFF") == 0) {
    log_message(LOG_INFO, "filter_ofcd(): url unknown");
    if (config.filter_blockunknown) {
      *status =
	  "The URL was not found in database and the filter is configured to block such URLs";
      return 0;
    }
    return 1;
  }

  DEBUG2("got answer: %s [%s]", buf, pat);

  while (len > 7) {
    unsigned char res;
    --len;
    if ((res = (htoi(pat[len]) & htoi(buf[len])))) {
      unsigned char mask = 1;
      int i;
      match = 0;

      if (catlist_initialized < 2)
	break;

      for (mask = 1, i = 0; i <= 3; i++) {
	if (res & mask) {
	  DEBUG2("match at:   %d bit %d: %s", 31 - len, i,
		 catlist[(31 - len) * 4 + i]);
	  outlen += snprintf(outbuf + outlen,
			     1024 - outlen, "<li>%s",
			     catlist[(31 - len) * 4 + i]);
	  if (outlen >= 1024)
	    break;
	}
	mask = mask << 1;
      }
    }
  }

  if (outlen)
    *status = outbuf;

  return match;

COMMON_ERROR:
  if (sockfd != -1)
    close(sockfd);
  return -1;
}

/* Return 0 to allow, non-zero to block */
int filter_domain(const char *host, const char *aclname, char **status)
{
  struct filter_list *f;
  struct filter_rulelist *p;
  int result;

  if (!fl || !filterlist_initialized || !(f = filter_get(aclname)))
    goto COMMON_EXIT;

  DEBUG2("%s: got filterlist for %s", __func__, aclname);

  for (p = f->rules; p; p = p->next) {

    switch (p->type) {
    case FL_ALLOW:
    case FL_DENY:
      result = regexec(p->cpat, host, (size_t) 0, (regmatch_t *) 0, 0);
      if (result == 0) {
	DEBUG2("%s:  match: %s", __func__, p->pat);
	if (p->type == FL_ALLOW)
	  return 0;
	else
	  return 1;
      }
      break;
    case FL_OFCD:
      result = filter_ofcd((const unsigned char *) p->pat, host, status);
      if (result == 0)
	return 2;
      else if (result == 1)
	return 0;
      break;
    default:
      DEBUG2("%s: filter type %d not yet supported", p->type);
    }
  }

COMMON_EXIT:
  if (config.default_policy == FILTER_ALLOW)
    return 0;
  else
    return 1;
}
