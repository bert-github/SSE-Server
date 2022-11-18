#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([SSE-Server], [0.1], [Bert Bos <bert@w3.org>])
AM_INIT_AUTOMAKE([-Wall])
AC_CONFIG_SRCDIR([sse-server.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_CPP

# Checks for libraries.
AC_CHECK_LIB([crypto], [CRYPTO_malloc], , AC_MSG_ERROR([libcrypto not found]))
AC_CHECK_LIB([ssl], [SSL_write], , AC_MSG_WARN([libssl not found]))

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memchr memmove memset memmem mkfifo socket strchr strcspn strdup strerror strndup strpbrk strrchr strtol])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
