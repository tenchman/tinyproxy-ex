CMAKE_MINIMUM_REQUIRED(VERSION 2.4)
PROJECT(tinyproxy-ex C)

SET(PACKAGE "tinyproxy-ex")
SET(VERSION "1.6.4.3")

# look if we have dietlibc installed and if so, build against it
FIND_PROGRAM(DIET diet PATH /opt/diet/bin /usr/bin /bin)
IF(DIET)
  MESSAGE("-- Found dietlibc gcc wrapper: ${DIET}")
  SET(CMAKE_C_COMPILER ${CMAKE_CURRENT_BINARY_DIR}/dietgcc)
  CONFIGURE_FILE(dietgcc.in ${CMAKE_CURRENT_BINARY_DIR}/dietgcc)
  SET(DIET_FOUND "YES")
ELSE(DIET)
  SET(DIET_FOUND "NO")
ENDIF(DIET)

SET(CMAKE_C_FLAGS "-Os -ffunction-sections -fdata-sections -I ${CMAKE_CURRENT_BINARY_DIR}/src -I ${CMAKE_CURRENT_SOURCE_DIR} -I ${CMAKE_CURRENT_SOURCE_DIR}/src")
SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--gc-sections")

SET(FTP_SUPPORT OFF CACHE BOOL
  "Enable support for ftp")
SET(UPSTREAM_SUPPORT ON CACHE BOOL
  "Include support for connecting to an upstream proxy.")
SET(FILTER_SUPPORT OFF CACHE BOOL
  "Enable filtering of domains/URLs.")
SET(PROCTITLE_SUPPORT OFF CACHE BOOL
  "Include support for status indicators via proctitle.")

SET(CONFIGDIR "/etc/${PACKAGE}" CACHE STRING
  "The location for configuraton files")
SET(CONFIGFILE "${PACKAGE}.conf" CACHE STRING
  "This is the default file name for the configuration file.")
SET(DEFAULT_STATHOST "${PACKAGE}.stats" CACHE STRING
  "This controls remote proxy stats display.")
SET(DATAROOTDIR "/usr/share/${PACKAGE}" CACHE STRING
  "The location for errorpages, styles and similar datafiles.")
SET(DEFAULT_CONF_FILE "${CONFIGDIR}/${CONFIGFILE}")

INCLUDE(CheckIncludeFile)
INCLUDE(CheckFunctionExists)
# INCLUDE(CheckTypeSize)

# check for required include files
INCLUDE(CheckIncludes.txt)
# check for required include functions
INCLUDE(CheckFunction.txt)
ADD_DEFINITIONS(-DHAVE_CONFIG_H)

CONFIGURE_FILE(config.h.in ${CMAKE_CURRENT_BINARY_DIR}/src/config.h)
CONFIGURE_FILE(doc/tinyproxy-ex.conf.in ${CMAKE_CURRENT_BINARY_DIR}/${CONFIGFILE})

FILE(GLOB icons "${CMAKE_CURRENT_SOURCE_DIR}/doc/icons/*.png")
FILE(GLOB html  "${CMAKE_CURRENT_SOURCE_DIR}/doc/*.html")
FILE(GLOB css   "${CMAKE_CURRENT_SOURCE_DIR}/doc/*.css")
INSTALL(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/src/tinyproxy DESTINATION sbin)
INSTALL(FILES ${icons} ${html} ${css} DESTINATION ${DATAROOTDIR})
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/${CONFIGFILE} DESTINATION ${CONFIGDIR})

FIND_PACKAGE(BISON)
FIND_PACKAGE(FLEX)

BISON_TARGET(GRAMMAR src/grammar.y  ${CMAKE_CURRENT_BINARY_DIR}/grammar.c)
FLEX_TARGET(SCANNER src/scanner.l ${CMAKE_CURRENT_BINARY_DIR}/scanner.c)
ADD_FLEX_BISON_DEPENDENCY(SCANNER GRAMMAR)

IF(FILTER_SUPPORT)
  SET(FILTER_SRC src/filter.c)
ENDIF()
IF(PROCTITLE_SUPPORT)
  SET(PROCTITLE_SRC src/proctitle.c)
ENDIF()
IF(FTP_SUPPORT)
  SET(FTP_SRC src/ftp.c)
ENDIF()
IF(NOT HAVE_WRITEV)
  SET(WRITEV_SRC src/writev.c)
ENDIF()
IF(NOT HAVE_REGEXEC)
  SET(REGEX_SRC src/gnuregex.c)
ENDIF()

SET(SOURCES
	src/acl.c
	src/anonymous.c
	src/buffer.c
	src/child.c
	src/conns.c
	src/daemon.c
	src/hashmap.c
	src/heap.c
	src/htmlerror.c
	src/http_message.c
	src/log.c
	src/network.c
	src/reqs.c
	src/sock.c
	src/stats.c
	src/text.c
	src/tinyproxy.c
	src/utils.c
	src/vector.c
)

ADD_EXECUTABLE(tinyproxy
	${BISON_GRAMMAR_OUTPUTS}
	${FLEX_SCANNER_OUTPUTS}
	${SOURCES} ${WRITEV_SRC} ${REGEX_SRC} ${FILTER_SRC} ${FTP_SRC}
	${PROCTITLE_SRC}
)

MESSAGE(" ================================================")
MESSAGE("  FTP support:         ${FTP_SUPPORT}")
MESSAGE("  Proctitle support:   ${PROCTITLE_SUPPORT}")
MESSAGE("  Upstream support:    ${UPSTREAM_SUPPORT}")
MESSAGE("  Build with dietlibc: ${DIET_FOUND}")
MESSAGE(" ================================================")
