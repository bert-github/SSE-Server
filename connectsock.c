/*
  connectsock() connects to a host and port over TCP or UDP. It
  returns a file descriptor suitable for reading and writing (but not
  seeking), or -1 in case of an error. The error is stored in errno.
  The port may be specified as a decimal number or as the name of a
  well-known service (listed in /etc/services).

  connectTCP() and connectUDP() are the same, but without the
  "protocol" argument. Instead, they always connect over TCP and UDP,
  respectively.

  passivesock() creates a server socket for TCP or UDP that listens on
  a port. It returns a file descriptor for reading and writing (as
  soon as a client connects to it), or -1 in case of an error. The
  error is stored in errno. The port may be specified as a decimal
  number or as the name of a well-known service (listed in
  /etc/services).

  passiveTCP() and passiveUDP() are the same, but without the
  "protocol" argument. Instead, they always use TCP and UDP,
  respectively.

  fconnectTCP() and fconnectUDP() are like the similarly named
  functions without "f", but return a FILE pointer instead of a file
  descriptor.

  Author: Bert Bos <bert@w3.org>
  Created: 12 May 1998
*/

#include "config.h"
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include "export.h"


/* connectsock -- allocate & connect a socket using TCP or UDP */
EXPORT int connectsock(const char * const host, const char * const service,
		       const char * const protocol)
{
  /* host = name of host to which connection is desired		*/
  /* service = service associated with the desired port		*/
  /* protocol = name of protocol to use ("tcp" or "udp")	*/
  struct addrinfo hints, *result, *rp;
  int t, s;

  /* Specify what type of connection we're looking for */
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;	/* Allow IPv4 or IPv6 */
  hints.ai_socktype = (strcmp(protocol, "udp") == 0) ? SOCK_DGRAM : SOCK_STREAM;
  hints.ai_flags = 0;
  hints.ai_protocol = 0;	/* Any protocol */

  /* Parse network address and service */
  if (getaddrinfo(host, service, &hints, &result) != 0) return -1;

  /* result is a linked list of address structures. */
  for (s = -1, rp = result; s == -1 && rp; rp = rp->ai_next) {
    if ((t = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) != -1) {
      if (connect(t, rp->ai_addr, rp->ai_addrlen) != -1) s = t; else close(t);
    }
  }
  freeaddrinfo(result);		/* Free the memory */
  return s;			/* If -1 no address succeeded */
}


/* connectTCP -- connect to a specified UDP service on a specified host */
EXPORT int connectTCP(const char * const host, const char * const service)
{
  return connectsock(host, service, "tcp");
}


/* connectUDP -- connect to a specified UDP service on a specified host */
EXPORT int connectUDP(const char * const host, const char * const service)
{
  return connectsock(host, service, "udp");
}


/* fconnectTCP -- connect to a specified TCP service on a specified host */
EXPORT FILE *fconnectTCP(const char * const host, const char * const service)
{
  int fd = connectTCP(host, service);
  return fd == -1 ? NULL : fdopen(fd, "r+");
}


/* fconnectUDP -- connect to a specified UDP service on a specified host */
EXPORT FILE *fconnectUDP(const char * const host, const char * const service)
{
  int fd = connectUDP(host, service);
  return fd == -1 ? NULL : fdopen(fd, "r+");
}


/* passivesock -- allocate & bind a server socket using TCP or UDP */
EXPORT int passivesock(const char * const service,
		       const char * const protocol, int qlen)
{
  /* service = service associated with the desired port		*/
  /* protocol = name of protocol to use ("tcp" or "udp")	*/
  /* qlen = maximum length of the server request queue		*/
  struct addrinfo hints, *result, *rp;
  int t, s;

  /* Specify what type of connection we're looking for */
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;			/* Allow IPv4 or IPv6 */
  hints.ai_socktype = (strcmp(protocol, "udp") == 0) ? SOCK_DGRAM : SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;			/* For wildcard IP address */
  hints.ai_protocol = 0;			/* Any protocol */
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  /* Parse network address and service */
  if (getaddrinfo(NULL, service, &hints, &result) != 0) return -1;

  /* result is a linked list of address structures. */
  for (s = -1, rp = result; s == -1 && rp; rp = rp->ai_next) {
    if ((t = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) != -1) {
      if (bind(t, rp->ai_addr, rp->ai_addrlen) != -1) s = t; else close(t);
    }
  }
  freeaddrinfo(result);				/* Free the memory */
  if (s == -1) return -1;			/* No address succeeded */

  /* If we want a TCP connection, also call listen(2) */
  if (hints.ai_socktype == SOCK_STREAM && listen(s, qlen) < 0) return -1;
  return s;
}


/* passiveTCP -- create a passive socket for use in a TCP server */
EXPORT int passiveTCP(const char * const service, int qlen)
{
  /* service = service associated with the desired port		*/
  /* qlen = maximum server request queue length			*/
  return passivesock(service, "tcp", qlen);
}


/* passiveUDP -- create a passive socket for use in a UDP server */
EXPORT int passiveUDP(const char * const service)
{
  return passivesock(service, "udp", 0);
}
