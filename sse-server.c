/*
SSE-Server implements an HTTP server for Server-Sent Events. It can be
controlled via commands on a FIFO or a dedicated socket. Those
commands also specify the events that it sends to connected web
clients.

An event in this case is an arbitrary text string in UTF-8. The
SSE-Server does not interpret it in any way. If the events need to
conform to a specific format (ASCII-only, JSON,
Unicode-normalized,etc.) they have to be formatted before giving them
to the SSE-Server.

Web clients connect to the server and subscribe to one or more
"channels", or to all channels. A channel name is an arbitrary text
string.



TODO: Support event types also on the FIFO.

TODO: An option to require authentication to connect to the control
port?

TODO: An option to require authentication on the SSE port? (But that
can also be handled by running the SSE-Server behind Apache or some
other HTTP server in proxy mode.)

TODO: Implement replay with the Last-Event-ID header.

TODO: Use HTTP/2.

TODO: Close connections after a certain time, configurable via an
option. Clients can reconnect if they are still interested. (When
running under an Apache as reverse proxy, Apache will close to
connection after 600 seconds of idleness, due to the "Keep-Alive:
timeout=600" header that we send.)

TODO: Escapes to allow arbitrary characters in events, for data that
contains newlines or binary data.

TODO: Shorten the allocated arrays "clients" and "pfds" when possible?
Currently, they only get longer (up to the limit imposed by the number
of open file descriptors.)

TODO: Use POST instead of GET for sending commands?

TODO: Allow a kind of "keep alive" by optionally sending a comment (a
line starting with ":") every 15 seconds or so to all web clients?

Created: 12 November 2022
Author: Bert Bos <bert@w3.org>
*/


#define _GNU_SOURCE		/* We want memmem(3) */
#include "config.h"
#include <unistd.h>
#include <limits.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <stdarg.h>
#include <err.h>
#include <sysexits.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ctype.h>
#include "export.h"
#include "connectsock.e"
#include "logger.e"
#include "memmem.e"

#ifndef POLLRDHUP		/* Only available if _GNU_SOURCE is defined */
#define POLLRDHUP 0
#endif

#define KEEP_ALIVE_INTERVAL 15 /* in seconds, to keep connections open */


/* File descriptors to poll(). The array is indexed by file
   descriptor. Unused entries have pfds[i].fd < 0 */
static struct pollfd *pfds = NULL;

/* clients is an array with information about each file descriptor.
   The array is indexed by file descriptor.

   If nchannels >= 0, the record describes a web client and nchannels
   is the number of channels the client is subscribed to. If nchannels
   is UNUSED, the entry is unused, otherwise if nchannels < 0, it
   specifies the type of connection: unused entry (UNUSED), a
   listening socket for new connections from web clients (WEB_SERVER),
   a listening socket for new connections from control clients
   (CONTROL_SERVER), a web client that sent a query
   (CONTROL_CLIENT_HTTP), a control client or FIFO (CONTROL_CLIENT),
   or a web client that is connected but did not send headers yet
   (INCOMPLETE_CLIENT).

   If a new connection is opened with a file descriptor higher than
   nclients, the array needs to be extended with realloc().

   All fields are initialized when the array is created or extended.
   If a connection is closed, allocated memory in the record is freed.
*/
#define UNUSED -7
#define LOGFILE -6
#define WEB_SERVER -5
#define CONTROL_SERVER -4
#define CONTROL_CLIENT_HTTP -3
#define CONTROL_CLIENT -2
#define INCOMPLETE_CLIENT -1

struct client_info {
  char host[NI_MAXHOST+1];  /* IP address of this client */
  char *inputbuf;	    /* For collecting data on partial reads */
  int inputlen;		    /* # of bytes collected in inputbuf */
  char **channels;	    /* Array of subscribed channels */
  int nchannels;	    /* # of channels or a client type if < 0 */
  SSL *ssl;		    /* SSL structure, or NULL if not encrypted */
  time_t last_write;	    /* Time of last write, used for keep-alives */
};
static struct client_info *clients = NULL;
static int nclients = 0;	/* Length of pfds and clients arrays */

static struct option longopts[] = {
  {"nodaemon", no_argument, NULL, 'n'},		 /* Default: daemonize */
  {"urlpath", required_argument, NULL, 'u'},	 /* Default: "/" */
  {"port", required_argument, NULL, 'p'},	 /* Default: 8080 */
  {"logfile", required_argument, NULL, 'l'},	 /* Default: none or stdout */
  {"cert", required_argument, NULL, 'c'},	 /* Default: none */
  {"privkey", required_argument, NULL, 'k'},	 /* Default: none */
  {"fifo", required_argument, NULL, 'F'},	 /* Default: none */
  {"controlport", required_argument, NULL, 'P'}, /* Default: none */
  {"user", required_argument, NULL, 'U'},	 /* Default: none */
  {"config", required_argument, NULL, 'C'},	 /* Default: none */
  {"allowc¥ommands", no_argument, NULL, 'a'},	 /* Default: don't allow */
  {"help", no_argument, NULL, 'h'},		 /* Default: no help */
  {NULL, 0, NULL, 0},
};

static SSL_CTX *ssl_context = NULL;
static bool allowcommands = false;
static bool stop = false;      /* Control the poll() loop in main() */


/* usage -- print error and usage message, then exit */
static void usage(const char *msg,...)
{
  va_list ap;

  va_start(ap, msg);
  if (msg) {vfprintf(stderr, msg, ap); fprintf(stderr, "\n");}
  fprintf(stderr, "Usage: sse-server [-n] [-u urlpath] [-p port] [-l logfile]"
	  " [-c ssl-cert] [-k ssl-privkey] [-f fifo] [-P controlport] [-U user]"
	  " [-C configfile] [-h]\n");
  va_end(ap);
  exit(EX_USAGE);
}


/* help -- print a short help text */
static void help(void)
{
  printf("sse-server sents server-sent events to HTTP clients\n");
  printf("Usage: sse-server [options]\n");
  printf("  --controlport, -P <port>  Listen for commands on <port>\n");
  printf("  --fifo, -F <file>         Listen for commands of <fifo>\n");
  printf("  --port, -p <port>         Listen for web clients on <port>\n");
  printf("  --url, -u <path>          URL path must begin with <path>\n");
  printf("  --cert, -c <certfile>     Turn on SSL, use certificate <cert>\n");
  printf("  --privkey, -k <privkey>   SSL private key from file <privkey>\n");
  printf("  --logfile, -l <file>      Append a log to <file>\n");
  printf("  --user, -U <user>         Run as <user>\n");
  printf("  --nodaemon, -n            Run in foreground\n");
  printf("  --allowcommands, -a       Allow commands in URL queries\n");
  printf("  --help, -h                This help\n");
  printf("At least one of --controlport and --fifo must be present.\n");
}


/* write2 -- write n bytes from buf to file fd, return # written or -1 */
static ssize_t write2(int fd, const void *buf, size_t n)
{
  SSL *ssl = clients[fd].ssl;
  return ssl ? SSL_write(ssl, buf, n) : write(fd, buf, n);
}


/* read2 -- read at most n bytes from file fd into buf, return # read or -1 */
static ssize_t read2(int fd, void *buf, size_t n)
{
  SSL *ssl = clients[fd].ssl;
  return ssl ? SSL_read(ssl, buf, n) : read(fd, buf, n);
}


/* init_unused_entry -- initialize an entry in the clients and pfds arrays */
static void init_unused_entry(int i)
{
  pfds[i].fd = -1;
  pfds[i].events = POLLIN | POLLRDHUP;
  clients[i].nchannels = UNUSED;
  clients[i].host[0] = '\0';
  clients[i].inputbuf = NULL;
  clients[i].inputlen = 0;
  clients[i].channels = NULL;
  clients[i].ssl = NULL;
  clients[i].last_write = 0;
}


/* close_client -- close a connection, clean up stored data */
static void close_client(const int fd)
{
  int i;

  /* If it was an encrypted connection, free the SSL structure. */
  if (clients[fd].ssl) {
    SSL_shutdown(clients[fd].ssl);
    SSL_free(clients[fd].ssl);
    clients[fd].ssl = NULL;
  }

  /* Close the connection. */
  close(fd);

  logger("Closing connection %d (%s)", fd, clients[fd].host);

  /* Free memory in the clients info. */
  free(clients[fd].inputbuf);
  for (i = 0; i < clients[fd].nchannels; i++) free(clients[fd].channels[i]);
  free(clients[fd].channels);

  /* Set clients[fd] to unused and pfds[fd] to -1. Set other fields to NULL. */
  init_unused_entry(fd);
}


/* accept_new_connection -- handle a new client connection */
static void accept_new_connection(const int sock, const int client_type)
{
  struct sockaddr address;
  socklen_t len = sizeof(address);
  char host[NI_MAXHOST] = "new connection";
  int fd, e;

  if ((fd = accept(sock, &address, &len)) == -1)
    log_err(EX_IOERR, "Accepting a new web connection");

  /* Log the IP address. */
  e = getnameinfo(&address, len, host, sizeof(host), NULL, 0, NI_NUMERICHOST);
  if (e == 0) logger("Got new %s connection %d from %s",
    client_type == CONTROL_CLIENT ? "controller" : "web", fd, host);
  else logger("Got new %s connection, could not get name: %s",
    client_type == CONTROL_CLIENT ? "controller" : "web", gai_strerror(e));

  /* Extend the pfds and clients array, if needed. */
  if (fd >= nclients) {
    if (!(pfds = realloc(pfds, (fd + 1) * sizeof(*pfds))))
      log_err(EX_OSERR, "Extending the array of file descriptors");
    if (!(clients = realloc(clients, (fd + 1) * sizeof(*clients))))
      log_err(EX_OSERR, "Extending the array of client information");
    while (nclients <= fd) init_unused_entry(nclients++);
  }

  /* Add the new file descriptor to the poll array. */
  pfds[fd].fd = fd;

  /* Initialize the client data for this file descriptor. */
  assert(clients[fd].channels == NULL && clients[fd].inputbuf == NULL);
  strcpy(clients[fd].host, host);
  clients[fd].nchannels = client_type;

  /* If we are using SSL, do the initial negotiation. Which may fail. */
  assert(clients[fd].ssl == NULL);
  if (ssl_context) {
    clients[fd].ssl = SSL_new(ssl_context);
    SSL_set_fd(clients[fd].ssl, fd);
    if (SSL_accept(clients[fd].ssl) <= 0) {
      logger("Cannot set up SSL to %d: %s", fd,
	ERR_error_string(ERR_get_error(), NULL));
      close_client(fd);
    }
  }
}


/* is_subscribed_to -- check if client fd is subscribed to any of channels */
static bool is_subscribed_to(const int fd, char **const channels, int nchannels)
{
  int i, j;

  if (clients[fd].nchannels < 0) return false; /* It's not a web client (yet) */
  if (clients[fd].nchannels == 0) return true; /* Client wants all */
  for (j = 0; j < clients[fd].nchannels; j++)
    for (i = 0; i < nchannels; i++)
      if (strcmp(clients[fd].channels[j], channels[i]) == 0) return true;
  return false;
}


/* create_chunk -- create HTTP chunk for message v, also return length */
static char *create_chunk(const char *t, const char *v, size_t *len)
{
  char *s = NULL;
  int i, n = 0;

  /* Compute the length of the data, without actually storing it. */
  if (strcmp(t, "message") == 0) /* Default event type is not sent */
    n = snprintf(s, 0, "data: %s\n\n", v);
  else
    n = snprintf(s, 0, "event: %s\ndata: %s\n\n", t, v);

  /* Compute the length of the header and trailer of the chunk. */
  i = snprintf(s, 0, "%X\r\n\r\n", n);

  /* Allocate n + i + 1 bytes (including \0), for the whole HTTP chunk. */
  if (!(s = malloc(n + i + 1)))
    log_err(EX_OSERR, "Allocating a string with event data");

  /* Now write the chunk into s. This should not fail. */
  if (strcmp(t, "message") == 0)
    sprintf(s, "%X\r\ndata: %s\n\n\r\n", n, v);
  else
    sprintf(s, "%X\r\nevent: %s\ndata: %s\n\n\r\n", n, t, v);

  assert(n + i >= 0);
  *len = n + i;
  return s;
}


/* write_all -- write all data to a socket */
static void write_all(const int fd, const void *data, size_t len)
{
  int i, n = len;
  const void *p = data;

  while (n != 0)
    if ((i = write2(fd, p, n)) >= 0) {
      p += i;
      n -= i;
    } else if (errno != EINTR) {
      log_warn("Writing to client %d", fd);
      close_client(fd);
    }

  /* Remember time, to know when to send the next keep-alive. */
  clients[fd].last_write = time(NULL);
}


/* send_event_to_web_clients -- send event t with data v to channels */
static void send_event_to_web_clients(char **const channels, int nchannels,
  const char *t, const char *v)
{
  char *chunk;
  bool found;
  size_t len;
  int j;

  chunk = create_chunk(t, v, &len);
  for (found = false, j = 0; j < nclients; j++)
    if (is_subscribed_to(j, channels, nchannels)) {
      write_all(j, chunk, len);
      logger("Sent event \"%s\" with data \"%s\" to web client %d (%s)",
	t, v, j, clients[j].host);
      found = true;
    }
  if (!found) logger("No subscribed web clients");
  free(chunk);
}


/* process_command -- process the command t */
static void process_command(const char *t)
{
  int j;

  if (strcmp(t, "halt") == 0) {

    stop = true;

  } else if (strcmp(t, "status") == 0) {

    logger("-------------------- Logfile --------------------");
    if (!logfile)
      logger("Not logging");
    else
      logger("%3d  %s", fileno(logfile), clients[fileno(logfile)].host);
    logger("------------------ Controllers ------------------");
    logger("  #  HOST           TYPE");
    for (j = 0; j < nclients; j++)
      if (clients[j].nchannels == CONTROL_CLIENT)
	logger("%3d  %-15s  socket", j, clients[j].host);
      else if (clients[j].nchannels == CONTROL_CLIENT_HTTP)
	logger("%3d  %-15s  HTTP", j, clients[j].host);
    logger("-------------------- Clients --------------------");
    logger("  #  HOST             CHANNELS");
    for (j = 0; j < nclients; j++) {
      switch (clients[j].nchannels) {
      case UNUSED:
      case LOGFILE:
      case WEB_SERVER:
      case CONTROL_SERVER:
      case CONTROL_CLIENT:
      case CONTROL_CLIENT_HTTP:
	break;
      case INCOMPLETE_CLIENT:
	logger("%3d  %-15s  waiting for headers", j, clients[j].host);
	break;
      case 0:
	logger("%3d  %-15s  all channels", j, clients[j].host);
	break;
      case 1:
	logger("%3d  %-15s  \"%s\"", j, clients[j].host,
	  clients[j].channels[0]);
	break;
      case 2:
	logger("%3d  %-15s  \"%s\", \"%s\"", j, clients[j].host,
	  clients[j].channels[0], clients[j].channels[1]);
	break;
      case 3:
	logger("%3d  %-15s  \"%s\", \"%s\", \"%s\"", j, clients[j].host,
	  clients[j].channels[0], clients[j].channels[1],
	  clients[j].channels[2]);
	break;
      default:
	assert(clients[j].nchannels >= 0);
	logger("%3d  %-15s  \"%s\", \"%s\", \"%s\"...", j, clients[j].host,
	  clients[j].channels[0], clients[j].channels[1],
	  clients[j].channels[2]);
	break;
      }
    }
    logger("-------------------------------------------------");

  } else {

    logger("Warning: Unknown command: %s", t);

  }
}


/* handle_command -- read a command from FIFO or control socket, then do it */
static void handle_command(const int fd)
{
  char *t, *u, *v, *end_of_line;
  int n;

  /* Make room in the input buffer for at least 1024 more bytes. */
  n = (clients[fd].inputlen + 1024 + 1024) / 1024 * 1024;
  if (!(clients[fd].inputbuf = realloc(clients[fd].inputbuf, n)))
    log_err(EX_OSERR, "Allocating a buffer for a command");

  n = read2(fd, clients[fd].inputbuf + clients[fd].inputlen, 1024);
  if (n == -1 && errno == EINTR) return;  /* Interrupted by a signal */
  if (n == -1) {log_warn("Reading a command"); close_client(fd); return;}

  clients[fd].inputlen += n;

  /* If we don't have the \n yet, we need to wait for more input. */
  if (!(end_of_line = memchr(clients[fd].inputbuf, '\n', clients[fd].inputlen)))
    return;

  /* When we're here, we have a complete line, including the \n. */

  /* Trim white space from start and end. */
  t = clients[fd].inputbuf;
  u = end_of_line;
  do {*u = '\0'; u--;} while (u != t && (*u == ' ' || *u == '\t'));
  while (*t == ' ' || *t == '\t') t++;

  if ((u = index(t, '='))) {	/* The line contains an event to send */

    v = u + 1; while (*v == ' ' || *v == '\t') v++; /* Start of event text */
    do *(u--) = '\0'; while (*u == ' ' || *u == '\t'); /* End of channel */
    /* TODO: allow escaped characters in the channel and message. */

    logger("Received from %d (%s): %s=%s", fd, clients[fd].host, t, v);

    /* Send to all clients interested in this channel. */
    if (!(u = index(t, '/'))) {	/* Split into channel and event type */
      send_event_to_web_clients(&t, 1, "message", v);
    } else {
      *u = '\0';
      send_event_to_web_clients(&t, 1, u + 1, v);
    }

  } else {			/* No '=' means it's a command */

    logger("Received from %d (%s): %s", fd, clients[fd].host, t);
    process_command(t);
  }

  /* Remove the line from inputbuf. */
  n = clients[fd].inputlen - (end_of_line + 1 - clients[fd].inputbuf);
  memmove(clients[fd].inputbuf, end_of_line + 1, n);
  clients[fd].inputlen = n;	/* Probably 0 */
}


/* reply_404 -- send a 404 Not Found and close the connection */
static void reply_404(const int fd)
{
  static char *s =
    "HTTP/1.1 404 Not Found\r\n"
    "Server: " PACKAGE_NAME "/" PACKAGE_VERSION "\r\n"
    "Content-Length: 10\r\n"
    "Content-Type: text/plain\r\n"
    "\r\n"
    "Not found\n";

  write_all(fd, s, strlen(s));
  close_client(fd);
}


/* reply_200 -- send a 200 OK with content-type text/event-stream */
static void reply_200(const int fd)
{
  static char s[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: " PACKAGE_NAME "/" PACKAGE_VERSION "\r\n"
    "Access-Control-Allow-Origin: *\r\n"
    "Access-Control-Allow-Methods: GET\r\n"
    "Access-Control-Allow-Headers: Cache-Control,Last-Event-Id,X-Requested-With\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Content-Type: text/event-stream\r\n"
    "Cache-Control: no-cache\r\n"
    "Keep-Alive: timeout=600, max=100\r\n"
    "Connection: Keep-Alive\r\n"
    "\r\n";

  write_all(fd, s, strlen(s));
}


/* reply_200_and_close -- send a 200 OK with a content of "OK" */
static void reply_200_and_close(const int fd)
{
  static char s[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: " PACKAGE_NAME "/" PACKAGE_VERSION "\r\n"
    "Access-Control-Allow-Origin: *\r\n"
    "Access-Control-Allow-Methods: GET\r\n"
    "Access-Control-Allow-Headers: Cache-Control,Last-Event-Id,X-Requested-With\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 4\r\n"
    "Cache-Control: no-cache\r\n"
    "\r\n"
    "OK\r\n";

  write_all(fd, s, strlen(s));
  close_client(fd);
}


/* reply_405 -- send a 400 Method Not Allowed and close the connection */
static void reply_405(const int fd)
{
  static char s[] =
    "HTTP/1.1 405 Method Not Allowed\r\n"
    "Server: " PACKAGE_NAME "/" PACKAGE_VERSION "\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 12\r\n"
    "\r\n"
    "Bad request\n";

  write_all(fd, s, strlen(s));
  close_client(fd);
}


/* hex -- return the value of a hexadecimal digit */
static char hex(char c)
{
  assert(isxdigit(c));
  return c <= '9' ? c - '0' : c <= 'F' ? 10 + c - 'A' : 10 + c - 'a';
}


/* unesc -- decode %-escapes in place, return a pointer to the start of s */
static char *unesc(char *s)
{
  char *t = s, *p = s;

  while (*t) {
    if (*t != '%' || !isxdigit(*(t+1)) || !isxdigit(*(t+2))) *p = *t;
    else {*p = 16 * hex(*(++t)); *p += hex(*(++t));}
    t++; p++;
  }
  *p = '\0';
  return s;
}


/* read_request -- read and interpret an HTTP request */
static void read_request(const int fd, const char *url_path)
{
  char *t, *end_of_headers, *q, *v, **channels, sep;
  int n = 1, len, nchannels;
  bool is_head;

  /* Make room in the input buffer for at least 1024 more bytes. */
  n = (clients[fd].inputlen + 1024 + 1024) / 1024 * 1024;
  if (!(clients[fd].inputbuf = realloc(clients[fd].inputbuf, n)))
    log_err(EX_OSERR, "Allocating a buffer for HTTP request headers");

  /* Read up to 1024 bytes. */
  n = read2(fd, clients[fd].inputbuf + clients[fd].inputlen, 1024);
  if (n == -1 && errno == EINTR) return;  /* Interrupted by a signal */
  if (n == -1) {log_warn("Reading an HTTP request"); close_client(fd); return;}
  if (n == 0) {close_client(fd); return;}

  clients[fd].inputlen += n;

  /* Check if we have the end of the headers and haven't parsed them yet. */
  if (clients[fd].nchannels >= 0)
    return;			/* Already parsed */
  if (!(end_of_headers = memmem(clients[fd].inputbuf, clients[fd].inputlen,
	"\r\n\r\n", 4)))
    return;			/* End of headers not seen yet */

  /* We have a complete set of headers that are not yet parsed. */
  t = clients[fd].inputbuf;
  n = strlen(url_path);

  /* We only handle HEAD and GET. */
  if (strncmp(t, "HEAD ", 5) == 0) {is_head = true; t += 5;}
  else if (strncmp(t, "GET ", 4) == 0) {is_head = false; t += 4;}
  else {reply_405(fd); return;}

  /* Check the requested URL path and send 404 if it is incorrect. */
  if (strncmp(t, url_path, n) != 0) {reply_404(fd); return;}

  /* If it was a HEAD, close the connection and we're done. */
  if (is_head) {reply_200_and_close(fd); return;}

  /* Parse all path segments after the prefix as channels. */
  if (n != 0 && url_path[n-1] == '/') n--; /* Don't count final '/' */
  channels = NULL;
  nchannels = 0;
  t += n;
  while (*t == '/') {
    len = strcspn(++t, "? /\r\n"); /* End at white space or at a query */
    if (len) {
      if (!(channels = realloc(channels, (nchannels + 1) * sizeof(*channels))))
	log_err(EX_OSERR, "Parsing request path");
      if (!(channels[nchannels++] = strndup(t, len)))
	log_err(EX_OSERR, "Parsing request path");
    }
    t += len;
  }

  /* If there is a query part, it's a controller, otherwise a web client. */
  if (*t != '?') {			/* No query -> web client */

    reply_200(fd);			/* Request was correct */

    /* Store the channels in the client info. */
    clients[fd].channels = channels;
    clients[fd].nchannels = nchannels;

    /* Remove the headers from inputbuf. */
    n = clients[fd].inputlen - (end_of_headers + 4 - clients[fd].inputbuf);
    memmove(clients[fd].inputbuf, end_of_headers + 4, n);
    clients[fd].inputlen = n;		/* Probably 0 */

    /* Log */
    switch (clients[fd].nchannels) {
    case 0:
      logger("Client %d requests all channels", fd);
      break;
    case 1:
      logger("Client %d requests channel \"%s\"",
	fd, clients[fd].channels[0]);
      break;
    case 2:
      logger("Client %d requests channels \"%s\" and \"%s\"",
	fd, clients[fd].channels[0], clients[fd].channels[1]);
      break;
    default:
      assert(clients[fd].nchannels >= 2);
      logger("Client %d requests channels \"%s\", \"%s\" and more",
	fd, clients[fd].channels[0], clients[fd].channels[1]);
      break;
    }

  } else {				/* Query -> controller */

    clients[fd].nchannels = CONTROL_CLIENT_HTTP;

    q = t;				/* Start of query, point to '?' */
    sep = *(++q);
    while (!strchr(" \r\n", sep)) {	/* Not yet at white space */
      t = q;				/* Start of parameter name */
      q = strpbrk(q, "&; \r\n");	/* End of parameter */
      sep = *q;				/* Remember the delimiter */
      *(q++) = '\0';			/* Mark end and advance */
      if ((v = strchr(t, '='))) {	/* End of parameter name */
	*(v++) = '\0';
	unesc(t); unesc(v);
	logger("Received from %d (%s): %s=%s", fd, clients[fd].host, t, v);
	send_event_to_web_clients(channels, nchannels, t, v);
      } else {				/* No '=', so it's a command */
	unesc(t);
	logger("Received from %d (%s): %s", fd, clients[fd].host, t);
	if (allowcommands) process_command(t);
	else logger("Commands not allowed from web clients.");
	/* TODO: Send a 403 instead of a 200? */
      }
    }

    reply_200_and_close(fd);		/* No more input expected */
  }
}


/* send_keep_alive -- send a no-op to a web client */
static void send_keep_alive(int fd)
{
  assert(clients[fd].nchannels >= 0);
  write_all(fd, "3\r\n:\n\n\r\n", 8);
}


/* read_config -- read options that are still unset from the configfile */
static void read_config(const char *filename, bool *nodaemon, char **url,
  char **port, char **logname, char **cert, char **privkey, char **fifoname,
  char **controlport, char **user, bool *allowcommands)
{
  char *line = NULL, *opt, *val, *t;
  size_t linecap = 0;
  FILE *f;

  if (!(f = fopen(filename, "r")))
    log_err(EX_NOINPUT, "Configuration file %s", filename);

  while (getline(&line, &linecap, f) != -1) {
    t = line;
    do opt = strsep(&t, " \t\r\n"); while (opt && opt[0] == '\0');
    do val = strsep(&t, " \t\r\n"); while (val && val[0] == '\0');
    if (!strcmp(opt, "nodaemon")) *nodaemon = true;
    else if (!strcmp(opt, "url") && !*url) *url = strdup(val);
    else if (!strcmp(opt, "port") && !*port) *port = strdup(val);
    else if (!strcmp(opt, "logfile") && !*logname) *logname = strdup(val);
    else if (!strcmp(opt, "cert") && !*cert) *cert = strdup(val);
    else if (!strcmp(opt, "provkey") && !*privkey) *privkey = strdup(val);
    else if (!strcmp(opt, "fifo") && !*fifoname) *fifoname = strdup(val);
    else if (!strcmp(opt, "controlport") && !*controlport) *controlport = strdup(val);
    else if (!strcmp(opt, "user") && !*user) *user = strdup(val);
    else if (!strcmp(opt, "allowcommands")) *allowcommands = true;
    else if (opt[0] == '#') ;	/* Comment */
    else if (opt[0]) errx(EX_DATAERR, "Unknown option in configfile: %s", opt);
  }
  if (ferror(f))
    log_err(EX_IOERR, "Configuration file %s", filename);

  free(line);
  fclose(f);
}


/* main -- main body */
int main(int argc, char *argv[])
{
  char *logname = NULL, *cert = NULL, *privkey = NULL, *fifoname = NULL,
    *user = NULL, *url_path = "/", *port = "8080", *controlport = NULL,
    *configname = NULL, *buf = NULL;
  int nready, c, fifo = -1, controlsock = -1, httpsock = -1, j, n;
  bool nodaemon = false;
  struct passwd *pw;
  time_t now;
  pid_t pid;

  while ((c = getopt_long(argc, argv, ":nu:u:p:l:c:k:F:P:U:C:ah", longopts,
	NULL)) != -1) {
    switch (c) {
    case 'n': nodaemon = true; break;
    case 'u': url_path = optarg; break;
    case 'p': port = optarg; break;
    case 'l': logname = optarg; break;
    case 'c': cert = optarg; break;
    case 'k': privkey = optarg; break;
    case 'F': fifoname = optarg; break;
    case 'P': controlport = optarg; break;
    case 'U': user = optarg; break;
    case 'C': configname = optarg; break;
    case 'a': allowcommands = true; break;
    case 'h': help(); exit(0);
    case ':': usage("Missing argument for option -%c", optopt);
    case '?': usage("Unknown or ambiguous option %c", optopt);
    default: assert(!"Unhandled command line option");
    }
  }
  if (argc > optind) usage("Unexpected argument: %s", argv[optind]);

  /* Read config file, if any, to set not yet specified options. */
  if (configname)
    read_config(configname, &nodaemon, &url_path, &port, &logname, &cert,
      &privkey, &fifoname, &controlport, &user, &allowcommands);

  /* Check the arguments. */
  if (cert && !privkey)
    errx(EX_USAGE, "Option --cert (-c) requires --privkey (-k)");
  if (!cert && privkey)
    errx(EX_USAGE, "Option --privkey (-k) requires --cert (-c)");
  if (*url_path != '/')
    errx(EX_USAGE, "The URL path (--url, -u) must start with a slash (/)");

  /* Log to stdout if running in foreground, or open a logfile for appending. */
  if (nodaemon) logfile = stdout;
  if (logname && !(logfile = fopen(logname, "a")))
    err(EX_NOINPUT, "Log file %s", logname);
  if (logfile) setlinebuf(logfile);

  /* Set up SSL, if requested. */
  if (cert) {
    if (!(ssl_context = SSL_CTX_new(TLS_server_method())))
      errx(EX_UNAVAILABLE, "Unable to create SSL context: %s",
	ERR_error_string(ERR_get_error(), NULL));
    if (SSL_CTX_use_certificate_file(ssl_context, cert, SSL_FILETYPE_PEM) <= 0)
      errx(EX_UNAVAILABLE, "Unable to use certificate %s: %s", cert,
	ERR_error_string(ERR_get_error(), NULL));
    if (SSL_CTX_use_PrivateKey_file(ssl_context, privkey, SSL_FILETYPE_PEM) <=0)
      errx(EX_UNAVAILABLE, "Unable to use private key %s: %s", privkey,
	ERR_error_string(ERR_get_error(), NULL));

    /* Do not aks for client certificates. */
    SSL_CTX_set_verify(ssl_context, SSL_VERIFY_NONE, NULL);
  }

  /* Switch users, if requested. */
  if (user) {
    errno = 0;
    if (!(pw = getpwnam(user))) {
      if (errno) err(EX_DATAERR, "Cannot switch to user %s", user);
      else errx(EX_NOUSER, "Unknown user: %s", user);
    }
    if (setuid(pw->pw_uid) == -1)
      err(EX_UNAVAILABLE, "Cannot switch to user %s", user);
  }

  /* Open the web server port. */
  if ((httpsock = passiveTCP(port, 100)) == -1)
    err(EX_CANTCREAT, "Cannot listen on %s", port);

  /* Open the FIFO, if requested. */
  if (fifoname) {
    if (mkfifo(fifoname, 0666) == -1 && errno != EEXIST)
      err(EX_CANTCREAT, "FIFO file %s", fifoname);
    if ((fifo = open(fifoname, O_RDWR, 0)) == -1)
      err(EX_NOINPUT, "FIFO file %s", fifoname);
  }

  /* Open the control socket, if requested. */
  if (controlport)
    if ((controlsock = passiveTCP(controlport, 100)) == -1)
      err(EX_CANTCREAT, "Cannot listen on %s", controlport);

  /* Go into the background, unless -n was specified. */
  if (!nodaemon) {
    if ((pid = fork()) == -1) err(EX_OSERR, "Cannot fork");
    if (pid == 0) {		/* Child */
      if (close(0) == -1) err(EX_OSERR, "Closing stdin");
      if (close(1) == -1) err(EX_OSERR, "Closing stdout");
      if ((pid = setsid()) == -1) err(EX_OSERR, "Disconnect from terminal");
    } else {			/* Parent */
      printf("Background process started, process id %d\n", pid);
      exit(0);
    }
  }

  /* Create and initialize the clients and pfds arrays. */
  if (fifo >= nclients) nclients = fifo + 1;
  if (controlsock >= nclients) nclients = controlsock + 1;
  if (httpsock >= nclients) nclients = httpsock + 1;
  if (!(clients = malloc(nclients * sizeof(*clients))))
    err(EX_OSERR, "Allocating client data");
  if (!(pfds = calloc(nclients, sizeof(*pfds))))
    err(EX_OSERR, "Allocating poll array");
  for (j = 0; j < nclients; j++) init_unused_entry(j);

  /* Initialize client info and poll array for the sockets. */
  if (fifo >= 0) {
    strcpy(clients[fifo].host, "FIFO"); /* fifoname may be too long */
    clients[fifo].nchannels = CONTROL_CLIENT;
    pfds[fifo].fd = fifo;
  }
  if (controlsock >= 0) {
    strcpy(clients[controlsock].host, "control port");
    clients[controlsock].nchannels = CONTROL_SERVER;
    pfds[controlsock].fd = controlsock;
  }
  if (httpsock >= 0) {
    strcpy(clients[httpsock].host, "http port");
    clients[httpsock].nchannels = WEB_SERVER;
    pfds[httpsock].fd = httpsock;
  }
  if (logfile) {
    strncat(clients[fileno(logfile)].host, logname ? logname : "<stdout>",
      sizeof(clients[0].host) - 1);
    clients[fileno(logfile)].nchannels = LOGFILE;
  }

  /* Mark the beginning of the log in the log file. */
  logger("===================================================");

  for (n = 9, j = 0; j < argc; j++) n += 1 + strlen(argv[j]);
  buf = malloc(n);
  strcpy(buf, "Command:");
  for (j = 0; j < argc; j++) strcat(strcat(buf, " "), argv[j]);
  logger("%s", buf);
  free(buf);

  if (configname) logger("Read configuration from %s", configname);
  logger("URL path prefix is %s", url_path);
  logger("Web server listening on port %s", port);
  if (logname) logger("Logging to file %s", logname);
  if (cert) logger("SSL enabled, cert %s and private key %s", cert, privkey);
  if (fifoname) logger("Controller listening on FIFO %s", fifoname);
  if (controlport) logger("Controller listening on port %s", controlport);
  if (user) logger("Running as user %s (%d)", user, pw->pw_uid);
  logger("Commands on control port %s", allowcommands ? "enabled" : "disabled");
  if (!nodaemon) logger("Running in background, process id %d", pid);

  /* Listen for connections, until killed. */
  while (!stop) {
    nready = poll(pfds, nclients, 1000 * KEEP_ALIVE_INTERVAL);
    if (nready == -1 && errno == EINTR) continue; /* Interrupted by signal */
    if (nready == -1) log_err(EX_OSERR, "While polling");

    now = time(NULL);

    /* Check each file descriptor if it has input waiting or is closed. */
    for (j = 0; j < nclients; j++) {
      if (pfds[j].fd < 0) continue;

      /* Handle incoming data (even if the connection is about to close) */
      if (pfds[j].revents & POLLIN &&
	clients[pfds[j].fd].nchannels == CONTROL_CLIENT)
	handle_command(pfds[j].fd);
      else if (pfds[j].revents & POLLIN &&
	clients[pfds[j].fd].nchannels == CONTROL_SERVER)
	accept_new_connection(pfds[j].fd, CONTROL_CLIENT);
      else if (pfds[j].revents & POLLIN &&
	clients[pfds[j].fd].nchannels == WEB_SERVER)
	accept_new_connection(pfds[j].fd, INCOMPLETE_CLIENT);
      else if (pfds[j].revents & POLLIN)
	read_request(pfds[j].fd, url_path);

      /* Next handle errors and closed connections, unless fd already closed. */
      if (pfds[j].revents & ~POLLIN && pfds[j].fd >= 0)
	close_client(pfds[j].fd);

      /* Send a no-op if a web client has been idle too long. */
      if (clients[j].nchannels >= 0 &&
	now > clients[j].last_write + KEEP_ALIVE_INTERVAL)
	send_keep_alive(j);
    }
  }

  /* TODO: Refuse connections if that would make nclients > RLIMIT_NOFILE */

  /* Close all clients. Send termination event to web clients. */
  for (j = nclients - 1; j >= 0; j--)
    if (pfds[j].fd >= 0) {
      if (clients[j].nchannels >= 0) write_all(j, "0\r\n\r\n", 5);
      close_client(j);
    }
  logger("Stopping");
  if (fifo) close(fifo);
  if (controlsock) close(controlsock);
  if (httpsock) close(httpsock);
  if (logfile) fclose(logfile);
  return 0;
}
