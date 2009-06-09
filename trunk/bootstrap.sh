#!/bin/sh
COPY=--copy

export PATH=/opt/diet/bin:$PATH
rm -rf autom4te.cache/

libtoolize -f --copy
aclocal
autoheader
automake --add-missing --copy
autoconf
