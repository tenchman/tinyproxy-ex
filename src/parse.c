#define _GNU_SOURCE /* strndup */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "conns.h"
#include "parse.h"
#include "log.h"

/*
 * See: https://tools.ietf.org/html/rfc3986#section-3.1
**/
int parse_request_line(request_t *req, struct conn_s *connptr) {
  char *line = connptr->request_line;
  size_t length = connptr->request_len;
  char *space;
  char *method = line;
  char *uri = NULL;
  char *proto = NULL;
  int ret = -ENOMEM;

  if (NULL == (space = memchr(line, ' ', length))) {
    /* missing first space */
    log_message(LOG_ERR, "missing first space");
    ret = -EINVAL;
  } else if (NULL == (method = strndup(line, space - line))) {
    /* OOM */
  } else {
    length -= (space - line - 1);
    line = ++space;
    if (NULL == (space = memchr(line, ' ', length))) {
      log_message(LOG_ERR, "missing second space");
      /* missing second space */
      ret = -EINVAL;
    } else if (NULL == (uri = strndup(line, space - line))) {
      /* OOM */
    } else {
      length -= (space - line - 1);
      line = ++space;
      if (NULL == (proto = strndup(line, length))) {
        /* OOM */
      } else {
	/* TODO: we have three pieces now, let check them */
	req->method = method;
	req->url = uri;
	req->protocol = proto;
        return 0;
      }
    }
  }

  free(method);
  free(proto);
  free(uri);
  return ret;
}
