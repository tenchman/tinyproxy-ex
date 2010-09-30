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

SET(DEFAULT_CONF_FILE "/etc/${PACKAGE}/${PACKAGE}.conf" CACHE STRING
  "This is the default file name for the configuration file.")
SET(DEFAULT_STATHOST "${PACKAGE}.stats" CACHE STRING
  "This controls remote proxy stats display.")
SET(DATAROOTDIR "/usr/share/${PACKAGE}" CACHE STRING
  "The location for errorpages, styles and similar datafiles.")

INCLUDE(CheckIncludeFile)
INCLUDE(CheckIncludeFileCXX)
INCLUDE(CheckFunctionExists)
INCLUDE(CheckTypeSize)

CONFIGURE_FILE(config.h.in ${CMAKE_CURRENT_BINARY_DIR}/src/config.h)
INCLUDE(CheckIncludes.txt)
ADD_DEFINITIONS(-DHAVE_CONFIG_H)

add_subdirectory(src)
