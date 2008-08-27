#!/bin/sh
rm -rf autom4te.cache/
aclocal
autoheader
libtoolize
automake --add-missing
autoconf
