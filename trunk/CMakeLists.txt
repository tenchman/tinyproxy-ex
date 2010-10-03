CMAKE_MINIMUM_REQUIRED(VERSION 2.4)
PROJECT(tinyproxy-ex C)

SET(PACKAGE "tinyproxy-ex")
SET(VERSION "1.6.4.3")
SET(CMAKE_C_COMPILER /opt/diet/bin/i386-tt-linux-dietlibc-gcc)
SET(CMAKE_C_FLAGS "-I ${CMAKE_CURRENT_BINARY_DIR}/src -I ${CMAKE_CURRENT_SOURCE_DIR} -I ${CMAKE_CURRENT_SOURCE_DIR}/src")

SET(FTP_SUPPORT ON CACHE BOOL
  "Enable support for ftp")
SET(UPSTREAM_SUPPORT ON CACHE BOOL
  "Include support for connecting to an upstream proxy.")
SET(FILTER_SUPPORT OFF CACHE BOOL
  "Include support for connecting to an upstream proxy.")
SET(PROCTITLE_SUPPORT ON CACHE BOOL
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
INCLUDE(CheckIncludeFileCXX)
INCLUDE(CheckFunctionExists)
INCLUDE(CheckTypeSize)

CONFIGURE_FILE(config.h.in ${CMAKE_CURRENT_BINARY_DIR}/src/config.h)
CONFIGURE_FILE(doc/tinyproxy-ex.conf.in ${CMAKE_CURRENT_BINARY_DIR}/${CONFIGFILE})
INCLUDE(CheckIncludes.txt)
ADD_DEFINITIONS(-DHAVE_CONFIG_H)

add_subdirectory(src)

FILE(GLOB icons "${CMAKE_CURRENT_SOURCE_DIR}/doc/icons/*.png")
FILE(GLOB html  "${CMAKE_CURRENT_SOURCE_DIR}/doc/*.html")
FILE(GLOB css   "${CMAKE_CURRENT_SOURCE_DIR}/doc/*.css")
INSTALL(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/src/tinyproxy DESTINATION sbin)
INSTALL(FILES ${icons} ${html} ${css} DESTINATION ${DATAROOTDIR})
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/${CONFIGFILE} DESTINATION ${CONFIGDIR})

