CONFIG_H_IN="config.h.in"
CHECK_INC="CheckIncludes.txt"
CMAKE_INC="autogen/CMakeIncludes.txt"
CHECK_FUNC="CheckFunction.txt"
CMAKE_FUNC="autogen/CMakeFunctions.txt"

echo -n > $CHECK_INC
echo -n > $CHECK_FUNC

cat >$CONFIG_H_IN<<__
#ifndef _CONFIG_H
#define _CONFIG_H 1

#define PACKAGE           "@PACKAGE@"
#define PACKAGE_NAME      "@PACKAGE@"
#define PACKAGE_STRING    "@PACKAGE@ @VERSION@"
#define VERSION           "@VERSION@"
#define DEFAULT_CONF_FILE "@DEFAULT_CONF_FILE@"
#define DEFAULT_STATHOST  "@DEFAULT_STATHOST@"
#define DATAROOTDIR       "@DATAROOTDIR@"
#define TARGET_SYSTEM     "@CMAKE_SYSTEM@"

#cmakedefine FILTER_SUPPORT	1
#cmakedefine UPSTREAM_SUPPORT	1
#cmakedefine FTP_SUPPORT	1
#cmakedefine PROCTITLE_SUPPORT	1

#define DEFAULT_CONF_FILE "@DEFAULT_CONF_FILE@"
#define DEFAULT_STATHOST  "@DEFAULT_STATHOST@"

__

while read head tail
do
  up=`echo $head | sed -e "s:[\./]:_:g" | tr '[:lower:]' '[:upper:]'`
  printf "CHECK_INCLUDE_FILE(%-16s HAVE_%s)\n" ${head} ${up} >> $CHECK_INC
  printf "/* %s */\n#cmakedefine HAVE_%s 1\n"  ${head} ${up} >> $CONFIG_H_IN
done < $CMAKE_INC


cat >>$CONFIG_H_IN<<__

/* ========================== */
/* Function section           */
/* ========================== */

__

while read head tail
do
  up=`echo $head | sed -e "s:[\./]:_:g" | tr '[:lower:]' '[:upper:]'`
  printf "CHECK_FUNCTION_EXISTS(%-16s HAVE_%s)\n" ${head} ${up} >> $CHECK_FUNC
  printf "/* %s() function */\n#cmakedefine HAVE_%s 1\n"  ${head} ${up} >> $CONFIG_H_IN
done < $CMAKE_FUNC

echo "#endif" >> $CONFIG_H_IN
