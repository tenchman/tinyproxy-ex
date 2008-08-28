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
#include "reqs.h"
#include "conns.h"
#include "utils.h"
#include "heap.h"
#include "buffer.h"
#include "log.h"

#define slash (info->type == 'd' ? "/" : "")

#define FTP_HEAD "<html><head>" \
  "<link rel='stylesheet' type='text/css' href='http:/""/" INTERNALNAME "/tinyproxy-ex.css'>" \
  "</head><body class='dirlist'><pre>"

struct ftpinfo_s {
  char type;
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
   * RFC 959 [Page 40]
   * format is: "227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)"
   */
  char *tmp = strchr(buf, '(');
  int h1, h2, h3, h4, p1, p2, port;

  if (!tmp)
    tmp = strchr(buf, '=');	/* EPLF */

  if (!tmp) {
    /* err */
  } else if (sscanf(++tmp, "%u,%u,%u,%u,%u,%u",
		    &h1, &h2, &h3, &h4, &p1, &p2) != 6) {
    /* err */
  } else if ((port = p1 * 256 + p2) > 65535 || port < 0) {
    /* err */
  } else {
    snprintf(host, INET_ADDRSTRLEN, "%d.%d.%d.%d", h1, h2, h3, h4);
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


static size_t *urldecode(char *path)
{
  int i;
  char *decoded = path;
  for (i = 0; i <= strlen(path); i++) {
    int a, b;
    if (path[i] == '%' &&
	((a = fromhex(path[i + 1])) != -1) &&
	((b = fromhex(path[i + 2])) != -1)) {
      *decoded++ = (a << 4) + b;
      i += 2;
    } else {
      *decoded++ = path[i];
    }
  }
  *decoded = '\0';
}

static char *urlencode(char *name)
{
  unsigned char *dst, *buf, *src = name;
  const unsigned char rfc1738unsafe[] = "<>\"#%{}|\\^~[]`' ";
  const unsigned char rfc1738reserved[] = ";/?:@=&";

  /* 
   * assume the worst case, all characters needs to be
   * encoded
   */
  dst = buf = safemalloc(strlen(src) * 3 + 1);

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
  return dst;
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

/*
 * Send a FTP-command to 'fd' and read the answer into 'buf'. We do some
 * parsing magic for 'motd' and other ugly things. If 'cmd' is omitted
 * (NULL), we only read the answer (i.e. after the initial connect).
 * 
 * TODO: Inform the caller if the buffer was to small.
 */
int send_and_receive(int fd, const char *cmd, char *buf, size_t buflen)
{
  size_t len, total = 0;
  struct timeval tv;
  char *pos = buf, *end, *tmp;
  int retval;

  if (cmd && write(fd, cmd, strlen(cmd)) == -1) {
    log_message(LOG_WARNING, "Failed to send %s", cmd);
    return -1;
  }

  /* 
   * really ugly parsing stuff for real long answers,
   * see "ftp.kernel.org" after PASS command
   */
  while (total < buflen) {
    len = read(fd, buf + total, buflen - total);
    if (len == -1) {
      log_message(LOG_WARNING, "Read error after command %s.", cmd);
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
  char buf[4096];
  int fd, code, port = 0;
  char *path, *file, *pathcopy, host[INET_ADDRSTRLEN];

  fd = opensock(request->host, request->port, buf, sizeof(buf));
  if (fd < 0) {
    log_message(LOG_WARNING, "Could not setup command channel.");
    indicate_http_error(connptr, 404, "Unable to setup command channel",
			"detail",
			"A network error occurred while trying to connect to the ftp server.",
			"error", buf, NULL);
    return -1;
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

  if ((code = send_and_receive(fd, "USER ftp\r\n", buf, sizeof(buf))) == -1)
    goto COMMON_ERROR_QUIT;

  switch (code) {
  case 331:
    if ((code = send_and_receive(fd, "PASS user@\r\n", buf, sizeof(buf))) == -1)
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

  /*
   * extract path and file components
   */
  path = pathcopy = safestrdup(request->path);

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
    if (file && *file)
      asprintf(&connptr->ftp_basedir, "%s/", file);
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
   * try to get the size of the requested file
   */

  /* TODO TODO TODO */

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

  connptr->server_cfd = fd;
  return connptr->server_fd;

COMMON_ERROR_QUIT:
  if (errbuf && errbufsize)
    strncpy(errbuf, buf, errbufsize - 1);
  send_and_receive(fd, "QUIT\r\n", buf, sizeof(buf));
  safefree(pathcopy);
  if (connptr->server_fd != -1)
    close(connptr->server_fd);
  close(fd);
  return -1;
}


static ssize_t fmt_direntry(char *buf, size_t buflen, struct ftpinfo_s *info)
{
  const char dots[32] = " . . . . . . . . . . . . . . . ";
  int nlen = 32 - strlen(info->name);
  char displayname[36];
  char *safename = urlencode(info->name);
  const char outfmt[] =
      "<a href=\"%s%s%s\"><img border=\"0\" src=\"http://tinyproxy-ex.intern/%c.png\" alt=\"[%c]\">"
      "</a> <a href=\"%s%s%s\">%s</a>%.*s %s %15llu   %s\r\n";

  /* crop the displayed name */
  strncpy(displayname, info->name, 31);
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

  safefree(safename);
  return nlen;
}

ssize_t add_ftpdir_header(struct conn_s * connptr)
{
  char buf[4096];
  size_t len;

  len = snprintf(buf, sizeof(buf), FTP_HEAD);
  add_to_buffer(connptr->sbuffer, buf, len);

  if (connptr->ftp_greeting)
    add_to_buffer(connptr->sbuffer, connptr->ftp_greeting,
		  strlen(connptr->ftp_greeting));

  len = snprintf(buf, sizeof(buf),
		 "</pre><h2>FTP Directory: %s</h2><hr><pre>\n",
		 connptr->ftp_path ? connptr->ftp_path : "");

  if (strcmp(connptr->ftp_path, "/"))
    len += snprintf(buf + len, sizeof(buf) - len, "<a href='..'>"
		    "<img border='0' src='http://tinyproxy-ex.intern/u.png' alt='up'>"
		    "</a> <a href='..'>Parent Directory</a>\r\n");

  return add_to_buffer(connptr->sbuffer, buf, len);
}

#define MAX_TOKENS 32
/*
 * TODO: Easily Parsed LIST Format - http://cr.yp.to/ftp/list/eplf.html
 *
 * Some ideas borowed from squid's ftp implementation
 */
static int scan_direntry(char *buf, size_t len, struct ftpinfo_s *info)
{
  char *t = NULL, *name;
  char *copy = safemalloc(len + 1);
  char *tokens[MAX_TOKENS];
  int i, n_tokens = 0, retval = -1;
  struct tm tm;
  char timebuf[32], *end;

  memset(tokens, 0, sizeof(tokens));
  strncpy(copy, buf, len);
  copy[len] = '\0';

  for (t = strtok(copy, " \t\n\r"); t && n_tokens < MAX_TOKENS;
       t = strtok(NULL, " \t\n\r"))
    tokens[n_tokens++] = safestrdup(t);

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

    snprintf(timebuf, sizeof(timebuf),
	     "%s %s %s", tokens[i], tokens[i + 1], tokens[i + 2]);

    /*
     * check if the is in one of the following formats:
     *      'Apr 17  2005'
     *      'Jun 25 00:37'
     */
    if (!strptime(timebuf, "%b %d %Y", &tm) &&
	!strptime(timebuf, "%b %d %H:%M", &tm))
      continue;

    info->size = strtoull(tokens[i - 1], &end, 10);
    if (end == tokens[i - 1])
      continue;

    snprintf(timebuf, sizeof(timebuf),
	     "%s %2s %5s", tokens[i], tokens[i + 1], tokens[i + 2]);

    if (!strstr(copy, timebuf))
      snprintf(timebuf, sizeof(timebuf), "%s %2s %-5s",
	       tokens[i], tokens[i + 1], tokens[i + 2]);

    info->type = *tokens[0];
    info->date = safestrdup(timebuf);
    info->link = NULL;

    if ((name = strstr(copy, timebuf))) {
      name += strlen(timebuf);
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
    snprintf(timebuf, sizeof(timebuf), "%s %s", tokens[0], tokens[1]);
    info->date = safestrdup(timebuf);
    info->name = safestrdup(tokens[3]);
    if (strcasecmp(tokens[2], "<dir>") == 0) {
      info->type = 'd';
      info->size = 0;
    } else {
      info->type = '-';
      info->size = strtoull(tokens[2], NULL, 10);
    }
    retval = 0;
    goto COMMON_EXIT;
  }

COMMON_EXIT:
  for (i = 0; i < n_tokens; i++)
    safefree(tokens[i]);
  safefree(copy);
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

  return add_to_buffer(buffptr, outbuf, outpos - outbuf);
}

#endif