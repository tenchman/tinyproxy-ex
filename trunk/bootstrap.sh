#!/bin/sh
rm -rf autom4te.cache/
aclocal --force
autoheader
libtoolize --force
automake --add-missing
autoconf
