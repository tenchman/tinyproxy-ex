/* $Id$
 *
 * Sockets are created and destroyed here. When a new connection comes in from
 * a client, we need to copy the socket and the create a second socket to the
 * remote server the client is trying to connect to. Also, the listening
 * socket is created and destroyed here. Sounds more impressive than it
 * actually is.
 *
 * Copyright (C) 1998  Steven Young
 * Copyright (C) 1999  Robert James Kaes (rjkaes@flarenet.com)
 * Copyright (C) 2000  Chris Lightfoot (chris@ex-parrot.com)
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

#include "log.h"

#include "sock.h"
#include "text.h"

struct sock_s {
  int fd;
  struct sockaddr_in addr;
  socklen_t len;
};

/* GT:
 * this struct holds informations about any of our addresses
 * we are listen on
**/
static struct listener_s {
  int total;			/* number of sock_s entries used        */
  int allocated;		/* number of sock_s entries allocated   */
  int maxfd;
  struct sock_s *sock;
} listeners = {
.total = 0,.allocated = 0,.maxfd = -1,.sock = NULL};

/*
 * Add and initialize a listener, update maxfd, total, etc.pp
**/
int add_listener(const char *addr, int port)
{
  struct sock_s s;

  memset(&s, 0, sizeof(s));
  s.addr.sin_family = AF_INET;
  s.addr.sin_addr.s_addr = inet_addr(addr);
  s.addr.sin_port = htons(port);

  if (listeners.total >= listeners.allocated) {
    struct sock_s *new;

    new = calloc(listeners.allocated + 10, sizeof(struct sock_s));
    if (!new) {
      fprintf(stderr, "listener_add: oom, exiting\n");
      exit(EXIT_FAILURE);
    }
    memcpy(new, listeners.sock, listeners.allocated * sizeof(struct sock_s));
    listeners.sock = new;
    listeners.allocated += 10;
  }
  memcpy(&listeners.sock[listeners.total], &s, sizeof(s));
  listeners.total++;
  return 0;
}

int listeners_total()
{
  return listeners.total;
}

static int do_connect(int sock_fd, struct addrinfo *rp, char *errbuf, size_t errbuflen)
{
  int ret = -1;
  socket_nonblocking(sock_fd);
  do {
    if (0 == (ret = connect(sock_fd, (struct sockaddr *) rp->ai_addr, rp->ai_addrlen))) {
      /* success */
    } else if (EINTR == errno) {
      continue;
    } else if (EINPROGRESS != errno) {
      snprintf(errbuf, errbuflen, "socket() error \"%s\".", strerror(errno));
    } else {
      struct timeval tv;
      fd_set fds;

      FD_ZERO(&fds);
      FD_SET(sock_fd, &fds);
      tv.tv_sec = config.connecttimeout;
      tv.tv_usec = 0;

      switch ((ret = select(sock_fd + 1, NULL, &fds, NULL, &tv))) {
      case -1:
	snprintf(errbuf, errbuflen, "socket() error \"%s\".", strerror(errno));
	break;
      case 0:
	snprintf(errbuf, errbuflen, "connection timeout.");
	break;
      default:
	ret = 0;
      }
    }
    break;
  } while(1);
  socket_blocking(sock_fd);
  return ret;
}

static const char* addrstr(char *dst, int len, struct addrinfo *rp)
{
  union {
    struct sockaddr_in *in;
    struct sockaddr_in6 *in6;
    struct sockaddr *a;
  } ptr = { .a = rp->ai_addr };
  const char *ret = NULL;

  memset(dst, 0, len);
  if (rp->ai_family == AF_INET6) {
    ret = inet_ntop(rp->ai_family, &ptr.in6->sin6_addr, dst, INET6_ADDRSTRLEN);
  } else {
    ret = inet_ntop(rp->ai_family, &ptr.in->sin_addr, dst, INET6_ADDRSTRLEN);
  }
  /* Work around a bug in dietlibc on 64bit systems */
  return ret ? dst : NULL;
}



/* This routine is so old I can't even remember writing it.  But I do
 * remember that it was an .h file because I didn't know putting code in a
 * header was bad magic yet.  anyway, this routine opens a connection to a
 * system and returns the fd.
 *	- steve
 *
 * Cleaned up some of the code to use memory routines which are now the
 * default. Also, the routine first checks to see if the address is in
 * dotted-decimal form before it does a name lookup.
 *      - rjkaes
 *
 * Rewrote the whole thing to use nonblocking connect
 *	- tenchio
 */
int opensock(char *host, uint16_t port, char *errbuf, size_t errbuflen)
{
  int sock_fd = -1;
  char ipbuf[INET6_ADDRSTRLEN];

  struct addrinfo hints;
  struct addrinfo *result, *rp;

  int r;
  char service[6];

  assert(host != NULL);
  assert(errbuf != NULL);
  assert(errbuflen > 0);
  assert(port > 0);

  snprintf(service, 6, "%hu", port);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  if (0 != (r = getaddrinfo(host, service, &hints, &result))) {
    snprintf(errbuf, errbuflen, "getaddrinfo() error \"%s\".", gai_strerror(r));;
  } else {
    /*
     * try to connect to the given address for each returned address
     */
    for (rp = result; rp; rp = rp->ai_next) {

      addrstr(ipbuf, sizeof(ipbuf), rp);

      if (-1 == (sock_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol))) {
	snprintf(errbuf, errbuflen, "can't create socket: \"%s\".", strerror(errno));
	log_message(LOG_ERR, "opensock: %s; %s", ipbuf, errbuf);
      } else if (-1 == do_connect(sock_fd, rp, errbuf, errbuflen)) {
	log_message(LOG_ERR, "opensock: %s; %s", ipbuf, errbuf);
	close(sock_fd);
	sock_fd = -1;
      } else {
	log_message(LOG_INFO, "connected to %s @ %s", host, ipbuf);
	break;
      }
    }
  }
  if (result)
    freeaddrinfo(result);
  return sock_fd;
}

/*
 * Set the socket to non blocking -rjkaes
 */
int socket_nonblocking(int sock)
{
  int flags;

  assert(sock >= 0);

  flags = fcntl(sock, F_GETFL, 0);
  return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

/*
 * Set the socket to blocking -rjkaes
 */
int socket_blocking(int sock)
{
  int flags;

  assert(sock >= 0);

  flags = fcntl(sock, F_GETFL, 0);
  return fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
}

/*
 * Start listening to a socket. Create a socket with the selected port.
 * The size of the socket address will be returned to the caller through
 * the pointer, while the socket is returned as a default return.
 *	- rjkaes
 */
int listen_sock(struct sock_s *sock)
{
  int listenfd;
  const int on = 1;

  assert(sock != NULL);

  listenfd = socket(AF_INET, SOCK_STREAM, 0);
  setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

  if (bind
      (listenfd, (struct sockaddr *) &sock->addr,
       sizeof(struct sockaddr_in)) < 0) {
    log_message(LOG_ERR, "Unable to bind listening: %s", strerror(errno));
    return -1;
  }

  if (listen(listenfd, MAXLISTEN) < 0) {
    log_message(LOG_ERR, "Unable to start listening: %s", strerror(errno));
    return -1;
  }

  return listenfd;
}

/*
 * wait for a connection on one of our listening sockets and
 * return the socket descriptor
**/
int accept_sock(void)
{
  int i, listenfd = -1, fd = -1;
  fd_set fds;

  FD_ZERO(&fds);

  for (i = 0; i < listeners.total; i++) {
    if (listeners.sock[i].fd != -1)
      FD_SET(listeners.sock[i].fd, &fds);
  }

  if (select(listeners.maxfd + 1, &fds, NULL, NULL, NULL) == -1) {
    log_message(LOG_ERR, "select() %s", strerror(errno));
    goto COMMON_EXIT;
  }

  for (i = 0; i < listeners.total; i++) {
    if (listeners.sock[i].fd == -1)
      continue;
    if (FD_ISSET(listeners.sock[i].fd, &fds)) {
      listenfd = listeners.sock[i].fd;
      break;
    }
  }

  if (listenfd == -1) {
    log_message(LOG_ERR, "accept_sock: unexpected event");
    goto COMMON_EXIT;
  }

  if ((fd = accept(listenfd, NULL, NULL)) == -1) {
    log_message(LOG_ERR, "accept() %s", strerror(errno));
    goto COMMON_EXIT;
  }

  log_message(LOG_INFO, "accepted connection on %d", fd);

COMMON_EXIT:
  return fd;
}

/*
 * start listening
 *
 * return 0 if at least one listener succeeds, -1 otherwise
**/
int start_listeners(void)
{
  int i;
  for (i = 0; i < listeners.total; i++) {
    int fd = listen_sock(&listeners.sock[i]);
    if (fd != -1) {
      listeners.maxfd = fd;
      log_message(LOG_NOTICE, "Start listening on %s:%d",
		  inet_ntoa(listeners.sock[i].addr.sin_addr),
		  ntohs(listeners.sock[i].addr.sin_port));
    }
    listeners.sock[i].fd = fd;
  }
  return listeners.maxfd;
}

/*
 * close all opened listeners
**/
void close_listeners(void)
{
  int i;
  for (i = 0; i < listeners.total; i++) {
    if (listeners.sock[i].fd != -1) {
      close(listeners.sock[i].fd);
      listeners.sock[i].fd = -1;
    }
  }
}

/*
 * Return the peer's socket information.
 */
int getpeer_information(int fd, char *ipaddr, char *string_addr)
{
  struct sockaddr_in name;
  socklen_t namelen = sizeof(name);
  struct hostent *result;

  assert(fd >= 0);
  assert(ipaddr != NULL);
  assert(string_addr != NULL);

  /*
   * Clear the memory.
   */
  memset(ipaddr, '\0', PEER_IP_LENGTH);
  memset(string_addr, '\0', PEER_STRING_LENGTH);

  if (getpeername(fd, (struct sockaddr *) &name, &namelen) != 0) {
    log_message(LOG_ERR, "getpeer_information: getpeername() error: %s",
		strerror(errno));
    return -1;
  } else {
    strlcpy(ipaddr,
	    inet_ntoa(*(struct in_addr *) &name.sin_addr.s_addr),
	    PEER_IP_LENGTH);
  }

  if (config.reverselookup) {
    result = gethostbyaddr((char *) &name.sin_addr.s_addr, 4, AF_INET);
    if (result)
      strlcpy(string_addr, result->h_name, PEER_STRING_LENGTH);
  }
  return 0;
}
