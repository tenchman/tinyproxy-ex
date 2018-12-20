#ifndef TINYPROXY_EX_PARSE_H
#define TINYPROXY_EX_PARSE_H 1

#include <sys/types.h>
#include "reqs.h"
#include "conns.h"

int parse_request_line(request_t *req, struct conn_s *connptr);

#endif
