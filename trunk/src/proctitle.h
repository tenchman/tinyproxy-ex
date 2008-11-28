#ifndef __PROCTITLE_H
#define __PROCTITLE_H 1

#include <config.h>

#ifdef PROCTITLE_SUPPORT
void proctitle(const char *format, ...);
void initproctitle(int argc, char **argv);
#else
#define proctitle(x, ...)
#define initproctitle(argc, argv)
#endif

#endif
