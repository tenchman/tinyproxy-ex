/* proctitle code - we know this to work only on linux... */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <libgen.h>
#include <stdarg.h>
#include <proctitle.h>

#ifdef PROCTITLE_SUPPORT

#ifndef SPT_BUFSIZE
#define SPT_BUFSIZE     2048
#endif

extern char **environ;
static char **argv0 = NULL;
static char *progname = NULL;
static size_t prognamelen;
static size_t available;
static size_t argv_len;

/* move away the environment to get space for our fancy
 * proctitle, initialize 'progname' and calculate 'prognamelen',
 * 'available' for later use.
**/
void initproctitle(int argc, char **argv)
{
  int i;
  char **envp = environ;

  /* initialize progname, prognamelen and available */
  if (argv && argv[0]) {
    progname = strdup(basename(argv[0]));
    prognamelen = strlen(progname);
    available = SPT_BUFSIZE - (prognamelen + 3);
  }

  /* count the environment entries */
  for (i = 0; envp[i] != NULL; i++);

  /* calculate the maximum argv length */
  argv0 = argv;
  if (i > 0)
    argv_len = envp[i - 1] + strlen(envp[i - 1]) - argv0[0];
  else
    argv_len = argv0[argc - 1] + strlen(argv0[argc - 1]) - argv0[0];
}

/* set process title
 *
 * The process title is set to the last component of the program name,
 * followed by a colon and the text specified by 'txt'.
 *
 * We name it simply proctitle to not conflict with the real BSDish
 * setproctitle(3) function.
**/
void proctitle(const char *format, ...)
{
  size_t i;
  char buf[SPT_BUFSIZE];
  va_list ap;

  if (!argv0)
    return;

  i = snprintf(buf, SPT_BUFSIZE, "%s: ", progname);

  va_start(ap, format);
  i += vsnprintf(buf + i, SPT_BUFSIZE - i, format, ap);
  va_end(ap);

  if (i > argv_len - 2)
    i = argv_len - 2;
  buf[i] = '\0';
  memset(argv0[0], 0, argv_len);	/* clear the memory area */
  memcpy(argv0[0], buf, i + 1);

  argv0[1] = NULL;
}

__attribute__((destructor)) void stopproctitle(void)
{
  free(progname);
}

#endif
