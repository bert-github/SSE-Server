/* Routines for logging and error messages */

#include <stdio.h>
#include <err.h>
#include <sysexits.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>
#include "export.h"

EXPORT FILE *logfile = NULL;


/* vlogger -- write a log message to the log file, if any */
EXPORT void vlogger(const char *message, va_list ap)
{
  if (logfile) {
    fprintf(logfile, "%10ld ", time(NULL));
    vfprintf(logfile, message, ap);
    fprintf(logfile, "\n");
  }
}


/* logger -- write a log message to the log file, if any */
EXPORT void logger(const char *message,...)
{
  va_list ap;

  va_start(ap, message);
  vlogger(message, ap);
  va_end(ap);
}


/* vlog_warnx -- write an error message to the log */
EXPORT void vlog_warnx(const char *fmt, va_list ap)
{
  char message[2048];
  int n = 0;

  if (logfile != stdout) {
    n += snprintf(message + n, sizeof(message) - n, "Error");
    if (fmt) {
      n += snprintf(message + n, sizeof(message) - n, ": ");
      n += vsnprintf(message + n, sizeof(message) - n, fmt, ap);
    }
    logger("%s", message);
  }
}


/* vlog_warn -- write an error message and strerror(errno) to the log */
EXPORT void vlog_warn(const char *fmt, va_list ap)
{
  char message[2048];
  int n = 0;

  if (logfile != stdout) {
    n += snprintf(message + n, sizeof(message) - n, "Error");
    if (fmt) {
      n += snprintf(message + n, sizeof(message) - n, ": ");
      n += vsnprintf(message + n, sizeof(message) - n, fmt, ap);
    }
    n += snprintf(message + n, sizeof(message) - n, ": %s", strerror(errno));
    logger("%s", message);
  }
}


/* log_warnx -- write an error message to the log */
EXPORT void log_warnx(const char *fmt,...)
{
  va_list ap;

  va_start(ap, fmt);
  vlog_warnx(fmt, ap);
  va_end(ap);
}


/* log_warn -- write an error message and strerror(errno) to the log */
EXPORT void log_warn(const char *fmt,...)
{
  va_list ap;

  va_start(ap, fmt);
  vlog_warn(fmt, ap);
  va_end(ap);
}


/* vlog_errx -- write an error message to the log and to stderr, then exit */
EXPORT void vlog_errx(int eval, const char *fmt, va_list ap)
{
  vlog_warnx(fmt, ap);
  verr(eval, fmt, ap);		/* Does not return */
}


/* vlog_err -- write an error message to the log and to stderr, then exit */
EXPORT void vlog_err(int eval, const char *fmt, va_list ap)
{
  vlog_warn(fmt, ap);
  verr(eval, fmt, ap);		/* Does not return */
}


/* log_errx -- write an error message to the log and to stderr, then exit */
EXPORT void log_errx(int eval, const char *fmt,...)
{
  va_list ap;

  va_start(ap, fmt);
  vlog_errx(eval, fmt, ap);	/* Does not return */
}


/* log_err -- write an error message to the log and to stderr, then exit */
EXPORT void log_err(int eval, const char *fmt,...)
{
  va_list ap;

  va_start(ap, fmt);
  vlog_err(eval, fmt, ap);	/* Does not return */
}


