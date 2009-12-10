/* $Id$
 *
 * Copyright (C) 2008  Gernot Tenchio (gernot@tenchio.de)
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
#ifdef FTP_SUPPORT
#include <sys/uio.h>		/* writev */
#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif
#include <time.h>		/* strptime */
#include <netinet/tcp.h>	/* TCP_NODELAY */
#include "reqs.h"
#include "network.h"
#include "conns.h"
#include "utils.h"
#include "heap.h"
#include "buffer.h"
#include "log.h"
#include "sock.h"
#include "htmlerror.h"

#define slash (info->type == 'd' ? "/" : "")

#define FTP_HEAD "<html><head>" \
  "<link rel='stylesheet' type='text/css' href='http:/""/" INTERNALNAME "/tinyproxy-ex.css'>" \
  "</head><body class='dirlist'><pre>"

struct ftpinfo_s {
  char type;
  char pad0[3];
  unsigned long long size;
  char *base;
  char *name;
  char *date;
  char *link;			/* never free link, it is only a pointer into name */
};

/*
 * get ip address and port for the data connection, the buffer
 * 'host' must be large enough to hold a ipv4 address
 */
static int parsepasv(char *buf, char *host)
{
  /* 
   * RFC 959 [Page 40] format is:
   *  "227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)"
   * DJB in contrast uses [http://cr.yp.to/ftp/retr.html]:
   *  "227 =h1,h2,h3,h4,p1,p2"
   */
  unsigned int h1, h2, h3, h4, p1, p2, port;
  /* skip return code and SP */
  char *tmp = buf + 4;

  /* advance to the first digit */
  while (*tmp && !(isdigit(*++tmp)));

  if (!*tmp) {
    /* err */
  } else if (sscanf(tmp, "%u,%u,%u,%u,%u,%u",
		    &h1, &h2, &h3, &h4, &p1, &p2) != 6) {
    /* err */
  } else if ((port = p1 * 256 + p2) > 65535) {
    /* err */
  } else {
    snprintf(host, INET_ADDRSTRLEN, "%u.%u.%u.%u", h1, h2, h3, h4);
    return port;
  }
  return -1;
}

static inline char tohex(char c)
{
  return c >= 10 ? c - 10 + 'A' : c + '0';
}

static int fromhex(unsigned char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  else {
    c |= ' ';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
  }
  return -1;
}

/* 
 * decode the url encoded path
 * Note: The original string gets overwritten!
 */
static void urldecode(char *path)
{
  size_t i;
  char *decoded = path;
  for (i = 0; i <= strlen(path); i++) {
    int a, b;
    if (path[i] == '%' &&
	((a = fromhex(path[i + 1])) != -1) &&
	((b = fromhex(path[i + 2])) != -1)) {
      if (a && b)		/* skip '\0' */
	*decoded++ = (a << 4) + b;
      i += 2;
    } else {
      *decoded++ = path[i];
    }
  }
  *decoded = '\0';
}

static char *urlencode(char *dst, char *name)
{
  unsigned char *buf = (unsigned char *) dst;
  unsigned char *src = (unsigned char *) name;
  const char rfc1738unsafe[] = "<>\"#%{}|\\^~[]`' ";
  const char rfc1738reserved[] = ";/?:@=&";

  if (!dst)
    return NULL;

  while (*src) {
    if ((*src <= (unsigned char) 0x1f) ||	/* control chars */
	(*src >= (unsigned char) 0x7f) ||	/* 0x7f, non-US-ASCII  */
	strchr(rfc1738unsafe, *src) || strchr(rfc1738reserved, *src)) {
      *buf++ = '%';
      *buf++ = tohex((*src & 0xf0) >> 4);
      *buf++ = tohex(*src & 0x0f);
    } else {
      *buf++ = *src;
    }
    src++;
  }
  *buf++ = '\0';
  return (char *) dst;
}

/*
 * we don't care if an error occurs, if so, we simply don't
 * have the greeting
 */
static void set_ftp_greeting(struct conn_s *connptr, char *str)
{
  char *buf, *tmp;

  if (!str || strncmp(str, "230-", 4))
    return;

  buf = connptr->ftp_greeting = safemalloc(strlen(str));

  if (buf == NULL)
    return;

  /*
   * copy all lines without the leading "230-"
   */
  while ((tmp = strstr(str, "\r\n"))) {
    if (strncmp(str, "230", 3) == 0)
      memset(str, ' ', 4);
    memcpy(buf, str, (tmp - str) + 2);
    buf += (tmp - str) + 2;
    str = tmp + 2;
  }
  /*
   * the last line is the status line, skip it
   */
  strcpy(buf, "\r\n");
}

#define HTTP_200_OK "HTTP/1.0 200 OK\r\n"
#define HEAD_CONN_CLOSE "Connection: close\r\n\r\n"

int send_ftp_response(struct conn_s *connptr)
{
  struct iovec iov[3];
  char buf[256];
  int n = 0;

  iov[n].iov_base = HTTP_200_OK;
  iov[n++].iov_len = sizeof(HTTP_200_OK) - 1;
  if (connptr->server.content_length != LENGTH_NONE) {
    iov[n].iov_base = buf;
    iov[n++].iov_len = snprintf(buf, 256, "Content-Length: %llu\r\n",
				connptr->server.content_length);
  }
  iov[n].iov_base = HEAD_CONN_CLOSE;
  iov[n++].iov_len = sizeof(HEAD_CONN_CLOSE) - 1;
  return writev(connptr->client_fd, iov, n);
}

/*
 * Send a FTP-command to 'fd' and read the answer into 'buf'. We do some
 * parsing magic for 'motd' and other ugly things. If 'cmd' is omitted
 * (NULL), we only read the answer (i.e. after the initial connect).
 * 
 * TODO: Inform the caller if the buffer was to small.
 */
int send_and_receive(int fd, const char *cmd, char *buf, size_t buflen)
{
  ssize_t len;
  size_t total = 0;
  char *pos = buf, *end, *tmp;
  int retval = -1, ret;
  fd_set sfd;
  struct timeval tv;

  tv.tv_sec = (long) config.idletimeout;
  tv.tv_usec = 0;

  if (cmd) {
#ifdef FTPDEBUG
    log_message(LOG_INFO, "send_and_receive, Sending command '%.*s'.",
		strlen(cmd) - 2, cmd);
#endif
    FD_ZERO(&sfd);
    FD_SET(fd, &sfd);
    switch ((ret = select(fd + 1, NULL, &sfd, NULL, &tv))) {
    case 0:
      log_message(LOG_ERR,
		  "send_and_receive, select() timeout while sending command '%.*s'",
		  strlen(cmd) - 2, cmd);
      return -1;
    case -1:
      log_message(LOG_ERR,
		  "send_and_receive, select() error while sending command '%.*s': %m",
		  strlen(cmd) - 2, cmd);
      return -1;
    default:
      ;
    }

    if (safe_send(fd, cmd, strlen(cmd)) == -1) {
      log_message(LOG_WARNING, "Failed to send command '%.*s'", cmd);
      return -1;
    }
  } else
    log_message(LOG_INFO, "send_and_receive, not sending any command");

  /* 
   * really ugly parsing stuff for real long answers,
   * see "ftp.kernel.org" after PASS command
   */
  while (total < buflen) {
    FD_ZERO(&sfd);
    FD_SET(fd, &sfd);
    switch ((ret = select(fd + 1, &sfd, NULL, NULL, &tv))) {
    case 0:
      log_message(LOG_ERR, "send_and_receive, select() timeout while reading");
      return -1;
    case -1:
      log_message(LOG_ERR,
		  "send_and_receive, select() error while reading, %m");
      return -1;
    default:
      ;
    }


    len = safe_recv(fd, buf + total, buflen - total);
#ifdef FTPDEBUG
    log_message(LOG_INFO, "send_and_receive, Got %d bytes.", len);
#endif
    if (len == -1) {
      log_message(LOG_WARNING, "send_and_receive, read error, %m");
      return -1;
    } else if (len == 0)
      break;

    total += len;
    buf[total] = '\0';
    while ((tmp = strstr(pos, "\r\n"))) {
      /*
       * the first character must be a digit, don't get
       * confused by things like:
       * "   100 Mbps connectivity courtesy of"...
       * as in the greeting of "ftp.netbsd.org"
       */
      if (isdigit(*pos)) {
	retval = strtol(pos, &end, 10);
#ifdef FTPDEBUG
	log_message(LOG_INFO, "send_and_receive, Got status '%.*s'.", tmp - pos,
		    pos);
#endif
	if (pos != end && *end == ' ')
	  goto FOUND;
      }
      pos = tmp + 2;
    }
  }

FOUND:
  return retval;
}

/*
 * connect to the remote host, setup a command and a data channel,
 * do all the ftp command stuff and return the file descriptor of
 * the data channel
 */
int
connect_ftp(struct conn_s *connptr, struct request_s *request, char *errbuf,
	    size_t errbufsize)
{
  char *tmp, buf[4096];
  int fd, code, port = 0, one = 1;
  char *path, *file, *pathcopy = NULL, host[INET_ADDRSTRLEN];
  long int size;
  char type = 0;

  fd = opensock(request->host, request->port, buf, sizeof(buf));
  if (fd < 0) {
    log_message(LOG_WARNING, "Could not setup command channel.");
    indicate_http_error(connptr, 404, "Unable to setup command channel",
			"detail",
			"A network error occurred while trying to connect to the ftp server.",
			"error", buf, NULL);
    return -1;
  }

  /* disable Nagle's algorithm for the command channel */
  if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == -1) {
    log_message(LOG_DEBUG, "setsockopt: unable to set TCP_NODELAY\n");
  }

  if ((code = send_and_receive(fd, NULL, buf, sizeof(buf))) == -1)
    goto COMMON_ERROR_QUIT;

  if (code != 220) {
    log_message(LOG_WARNING, "Connect: Unexpected answer: %s", buf);
    goto COMMON_ERROR_QUIT;
  }

  /*
   * try to login as user 'ftp' with password 'user@'
   */

  if ((code =
       send_and_receive(fd, "USER anonymous\r\n", buf, sizeof(buf))) == -1)
    goto COMMON_ERROR_QUIT;

  switch (code) {
  case 331:
    if ((code =
	 send_and_receive(fd, "PASS ftp@" PACKAGE_NAME ".org\r\n", buf,
			  sizeof(buf))) == -1)
      goto COMMON_ERROR_QUIT;
    if (code != 230) {
      log_message(LOG_WARNING, "PASS: Unexpected answer: %s", buf);
      goto COMMON_ERROR_QUIT;
    }
    /* fall through */
  case 230:
    set_ftp_greeting(connptr, buf);
    break;
  default:
    log_message(LOG_WARNING, "USER: Unexpected answer: %s", buf);
    goto COMMON_ERROR_QUIT;
  }

  /* decode url encoded paths */
  urldecode(request->path);

  path = pathcopy = safestrdup(request->path);

  /* 
   * extract the type from "lftp" style urls, i.e.
   * GET ftp://ftp.somewhere.loc/dingens.ext;type=i HTTP/1.1
   */
  if ((tmp = strrchr(path, ';'))) {
    if (strncasecmp(tmp + 1, "type=", 5) == 0) {
      type = (char) *(tmp + 6);
      *tmp = '\0';
    }
  }

  /*
   * extract path and file components
   */
  if (pathcopy[strlen(pathcopy)] == '/') {
    file = NULL;
  } else if ((file = strrchr(pathcopy, '/')) == NULL) {
    file = pathcopy;
    path = NULL;
  } else {
    *file = '\0';
    file++;
    if (!*path)
      path = NULL;		/* top level directory */
  }
  /*
   * now change the directory, first try the full path to
   * see whether it is a file or directory. If that fails, try
   * to CWD to the path component (if any).
   */
  snprintf(buf, sizeof(buf), "CWD %s\r\n", request->path);
  if ((code = send_and_receive(fd, buf, buf, sizeof(buf))) == -1)
    goto COMMON_ERROR_QUIT;

  if (code == 250 || code == 230) {
    if (file && *file) {
      ssize_t flen = strlen(file);
      connptr->ftp_basedir = safemalloc(flen + 2);
      memcpy(connptr->ftp_basedir, file, flen);
      connptr->ftp_basedir[flen] = '/';
      connptr->ftp_basedir[flen + 1] = '\0';
    }
    file = NULL;
    connptr->ftp_path = safestrdup(request->path);
  } else if (path) {
    snprintf(buf, sizeof(buf), "CWD %s\r\n", path);
    if ((code = send_and_receive(fd, buf, buf, sizeof(buf))) == -1)
      goto COMMON_ERROR_QUIT;

    if (code != 250 && code != 230) {
      log_message(LOG_WARNING, "CWD: Unexpected answer: (%d), %s", code, buf);
      goto COMMON_ERROR_QUIT;
    }
    connptr->ftp_path = safestrdup(path);
  }

  /* 
   * lftp sends "HEAD xyz HTTP/x.x" for "CWD xyz". If so,
   * send a QUIT to the server and simply return 0.
   */
  if (strcmp(request->method, "HEAD") == 0) {
    send_and_receive(fd, "QUIT\r\n", buf, sizeof(buf));
    safefree(pathcopy);
    return 0;
  }

  /* 
   * now get the port for the data connection.
   */
  if ((code = send_and_receive(fd, "PASV\r\n", buf, sizeof(buf))) == -1)
    goto COMMON_ERROR_QUIT;

  if (code != 227 || (port = parsepasv(buf, host)) == -1) {
    log_message(LOG_WARNING, "PASV: Unexpected answer: %d %s", port, buf);
    goto COMMON_ERROR_QUIT;
  }

  /*
   * open the data connection
   */
  connptr->server_fd = opensock(host, port, buf, sizeof(buf));
  if (connptr->server_fd == -1) {
    log_message(LOG_WARNING, "Could not setup data channel. %s", buf);
    indicate_http_error(connptr, 404, "Unable to setup data channel",
			"detail",
			"A network error occurred while trying to connect to the ftp server.",
			"error", buf, NULL);
    goto COMMON_ERROR_QUIT;
  }
  DEBUG2("opened connection %s:%d (fd:%d)", host, port, connptr->server_fd);

  /*
   * Send the command to receive the file or to retrieve a
   * directory listing.
   */
  if (file) {

    if (!type)
      type = 'i';
    snprintf(buf, sizeof(buf), "TYPE %c\r\n", toupper(type));
    if ((code = send_and_receive(fd, buf, buf, sizeof(buf))) == -1)
      goto COMMON_ERROR_QUIT;

    /*
     * try to get the size of the requested file
     */
    snprintf(buf, sizeof(buf), "SIZE %s\r\n", file);
    if ((code = send_and_receive(fd, buf, buf, sizeof(buf))) == -1)
      goto COMMON_ERROR_QUIT;

    if (code == 213 && (size = strtol(buf + 4, NULL, 10)))
      connptr->server.content_length = size;

    /*
     * now send the command to retrieve the file
     */
    snprintf(buf, sizeof(buf), "RETR %s\r\n", file);
    DEBUG2("sending RETR %s", file);
    if ((code = send_and_receive(fd, buf, buf, sizeof(buf))) == -1)
      goto COMMON_ERROR_QUIT;
    switch (code) {
    case 125:
    case 150:
    case 226:
    case 250:
      break;
    default:
      log_message(LOG_WARNING, "RETR: Unexpected answer: %s", buf);
      goto COMMON_ERROR_QUIT;
    }
    connptr->ftp_isdir = FALSE;
  } else {
    DEBUG2("sending LIST");
    if ((code = send_and_receive(fd, "LIST\r\n", buf, sizeof(buf))) == -1)
      goto COMMON_ERROR_QUIT;

    switch (code) {
    case 125:
    case 150:
      break;
    default:
      log_message(LOG_WARNING, "LIST: Unexpected answer: %s", buf);
      goto COMMON_ERROR_QUIT;
    }
    connptr->ftp_isdir = TRUE;
  }

  safefree(pathcopy);
  connptr->server_cfd = fd;
  return connptr->server_fd;

COMMON_ERROR_QUIT:
  if (errbuf && errbufsize)
    strncpy(errbuf, buf, errbufsize - 1);
  send_and_receive(fd, "QUIT\r\n", buf, sizeof(buf));
  safefree(pathcopy);
  if (connptr->server_fd != -1)
    close(connptr->server_fd);
  connptr->statuscode = code;
  close(fd);
  return -1;
}


static ssize_t fmt_direntry(char *buf, size_t buflen, struct ftpinfo_s *info)
{
  const char dots[32] = " . . . . . . . . . . . . . . . ";
  int nlen = 32 - strlen(info->name);
  char displayname[36];
  char *safename;
  const char outfmt[] =
      "<a href=\"%s%s%s\"><img border=\"0\" src=\"http://tinyproxy-ex.intern/%c.png\" alt=\"[%c]\">"
      "</a> <a href=\"%s%s%s\">%s</a>%.*s %s %15llu   %s\r\n";

  /* 
   * assume the worst case, all characters needs to be
   * encoded
   */
#ifdef HAVE_ALLOCA
  safename = alloca(strlen(info->name) * 3 + 1);
#else
  safename = malloc(strlen(info->name) * 3 + 1);
#endif
  urlencode(safename, info->name);

  /* crop the displayed name */
  strncpy(displayname, info->name, 31);
  displayname[31] = '\0';
  if (nlen <= 0) {
    memcpy(&displayname[30], "&gt;", 5);
    nlen = 0;
  }

  nlen = snprintf(buf, buflen, outfmt, info->base, safename, slash,	/* link */
		  info->type, info->type, info->base, safename, slash,	/* link */
		  displayname,
		  nlen,
		  dots + (32 - nlen),
		  info->date, info->size, info->link ? info->link : "");

#ifndef HAVE_ALLOCA
  safefree(safename);
#endif
  return nlen;
}

ssize_t add_ftpdir_header(struct conn_s * connptr)
{
  char buf[4096];
  size_t len;

  len = snprintf(buf, sizeof(buf), FTP_HEAD);
  add_to_buffer(connptr->sbuffer, (unsigned char *) buf, len);

  if (connptr->ftp_greeting)
    add_to_buffer(connptr->sbuffer, (unsigned char *) connptr->ftp_greeting,
		  strlen(connptr->ftp_greeting));

  len = snprintf(buf, sizeof(buf),
		 "</pre><h2>FTP Directory: %s</h2><hr><pre>\n",
		 connptr->ftp_path ? connptr->ftp_path : "");

  if (strcmp(connptr->ftp_path, "/"))
    len += snprintf(buf + len, sizeof(buf) - len, "<a href='..'>"
		    "<img border='0' src='http://tinyproxy-ex.intern/u.png' alt='up'>"
		    "</a> <a href='..'>Parent Directory</a>\r\n");

  return add_to_buffer(connptr->sbuffer, (unsigned char *) buf, len);
}

#define MAX_TOKENS 32
/*
 * TODO: Easily Parsed LIST Format - http://cr.yp.to/ftp/list/eplf.html
 *
 * Some (well most) ideas borowed from squid's ftp implementation
 */
static int scan_direntry(char *buf, size_t len, struct ftpinfo_s *info)
{
  char *t = NULL, *name;
#ifdef HAVE_ALLOCA
  char *copy = safemalloc(len + 1);
#else
  char *copy = alloca(len + 1);
#endif
  char *tokens[MAX_TOKENS];
  int i, n_tokens = 0, retval = -1;
  struct tm tm;
  char tmp[64], *end;

  memset(tokens, 0, sizeof(tokens));
  strncpy(copy, buf, len);
  copy[len] = '\0';

  for (t = strtok(copy, " \t\n\r"); t && n_tokens < MAX_TOKENS;
       t = strtok(NULL, " \t\n\r"))
#ifdef HAVE_ALLOCA
  {
    tokens[n_tokens] = alloca(strlen(t) + 1);
    strcpy(tokens[n_tokens], t);
    n_tokens++;
  }
#else
    tokens[n_tokens++] = safestrdup(t);
#endif

  if (n_tokens < 4 && tokens[0][0] != '+') {
    /* return -2 to ignore this line */
    retval = -2;
    goto COMMON_EXIT;
  }

  /* restore the copy */
  strncpy(copy, buf, len);
  /*
   * first try some unix formats
   * 
   * ftp.netbsd.org
   *    "drwxr-x--x  3 root      wheel          512 Jul 21 11:23 etc"
   *
   * ftp.gnome.org
   *    "drwxr-xr-x    5 1113     1112         4096 May 30  2007 pub"
   */
  for (i = 3; i < n_tokens - 2; i++) {

    snprintf(tmp, sizeof(tmp),
	     "%s %s %s", tokens[i], tokens[i + 1], tokens[i + 2]);

    /*
     * check if the is in one of the following formats:
     *      'Apr 17  2005'
     *      'Jun 25 00:37'
     */
    if (!strptime(tmp, "%b %d %Y", &tm) && !strptime(tmp, "%b %d %H:%M", &tm))
      continue;

    info->size = strtoull(tokens[i - 1], &end, 10);
    if (end == tokens[i - 1]) {
      /*
       * extra hack for listings where group and filesize touches each other
       * i.e. ftp://ftp.cisco.com/pub/isgtech/
       *
       * -rw-r--r--    1 ftpadmin ftpadmin556818432 Dec 12  2007 DMS-4.1.0.40.iso
       */
      char *tmp = tokens[i - 1];
      while (!isdigit(*tmp))
	tmp++;
      info->size = strtoull(tmp, &end, 10);
      if (end == tmp)
	continue;
    }

    snprintf(tmp, sizeof(tmp),
	     "%s %2s %5s", tokens[i], tokens[i + 1], tokens[i + 2]);

    if (!strstr(copy, tmp))
      snprintf(tmp, sizeof(tmp), "%s %2s %-5s",
	       tokens[i], tokens[i + 1], tokens[i + 2]);

    info->type = *tokens[0];
    info->date = safestrdup(tmp);
    info->link = NULL;

    if ((name = strstr(copy, tmp))) {
      name += strlen(tmp);
      while (strchr(" \t\n\r", *name))
	name++;
      info->name = safestrdup(name);
      if (info->type == 'l' && (t = strstr(info->name, " -> "))) {
	*t = '\0';
	info->link = t + 1;
      }
    } else {
      info->name = safestrdup(tokens[i + 3]);
    }

    retval = 0;
    goto COMMON_EXIT;
  }

  /* 
   * DOS Format
   *   - "02-01-06  04:31PM       <DIR>          lanman"
   */
  if (strptime(tokens[0], "%m-%d-%y", &tm)
      && strptime(tokens[1], "%H:%M%p", &tm)) {
    snprintf(tmp, sizeof(tmp), "%s %s", tokens[0], tokens[1]);
    info->date = safestrdup(tmp);
    info->link = NULL;

    if (strcasecmp(tokens[2], "<dir>") == 0) {
      info->type = 'd';
      info->size = 0;
      if ((name = strstr(copy, tokens[2])))
	name += strlen(tokens[2]);
    } else {
      info->type = '-';
      info->size = strtoull(tokens[2], NULL, 10);
      snprintf(tmp, sizeof(tmp), " %s %s", tokens[2], tokens[3]);
      if ((name = strstr(copy, tmp)))
	name += strlen(tokens[2]) + 2;
    }

    if (name) {
      while (isspace(*name))
	name++;
      info->name = safestrdup(name);
    } else {
      info->name = safestrdup(tokens[3]);
    }
    retval = 0;
  }

COMMON_EXIT:
#ifndef HAVE_ALLOCA
  for (i = 0; i < n_tokens; i++)
    safefree(tokens[i]);
  safefree(copy);
#endif
  return retval;
}


ssize_t
add_to_buffer_formatted(struct buffer_s * buffptr, unsigned char *inbuf,
			size_t buflen, struct conn_s * connptr)
{
  static char buf[READ_BUFFER_SIZE * 2] = { 0 };
  char outbuf[READ_BUFFER_SIZE * 4] = { 0 };
  char *this, *next, *outpos, *eob;
  struct ftpinfo_s info;
  size_t len;

  if (buflen + connptr->offset >= sizeof(buf)) {
    log_message(LOG_ERR, "overlong line. %d", buflen + connptr->offset);
    return -1;
  }

  memcpy(buf + connptr->offset, inbuf, buflen);

  buf[connptr->offset + buflen] = '\0';

  outpos = outbuf;
  this = buf;
  eob = buf + buflen + connptr->offset;

  info.base = connptr->ftp_basedir ? connptr->ftp_basedir : "";

  do {
    next = strstr(this, "\r\n");
    if (!next) {
      /* 
       * Need more data, move the remaining bytes to the
       * beginning of our buffer and adjust the offset
       */
      connptr->offset = eob - this;
      memmove(buf, this, connptr->offset);
      break;
    }


    switch (scan_direntry(this, next - this, &info)) {
    case -1:
      /*
       * unexpected format, copy directly to outbuf
       */
      memcpy(outpos, this, (next - this) + 2);
      /* fall through */
    case -2:
      outpos += (next - this) + 2;
      break;
    default:
      len = 0;
      /*
       * skip "." and ".." directories, seen on
       * ftp://ecos.sourceware.org/
       */
      if (info.name[0] != '.' && (info.name[1] != '.' || info.name[1] != '\0'))
	len = fmt_direntry(outpos, sizeof(outbuf) - (outpos - outbuf), &info);

      safefree(info.date);
      safefree(info.name);

      /*
       * this should really handled nicer. Kill me if you
       * can.
       */
      if ((outpos += len) > outbuf + sizeof(outbuf)) {
	log_message(LOG_ERR, "buffer to small. %d < %d",
		    sizeof(outbuf), outpos - outbuf);
	return -1;
      }
    }
    this = next + 2;
  } while (this <= eob);

  return add_to_buffer(buffptr, (unsigned char *) outbuf, outpos - outbuf);
}

#endif
