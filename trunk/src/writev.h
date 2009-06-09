#ifndef _WRITEV_H
#define _WRITEV_H 1

#include <config.h>
#ifdef HAVE_WRITEV
#include <sys/uio.h>
#else

#include <sys/types.h>

struct iovec {
  void *iov_base;		/* Starting address */
  size_t iov_len;		/* Number of bytes to transfer */
};

ssize_t writev(int fd, const struct iovec *iov, int iovcnt);

#endif
#endif
