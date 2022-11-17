/* connectsock.c
 *
 * Part of HTML-XML-utils, see:
 * http://www.w3.org/Tools/HTML-XML-utils/
 *
 * Copyright © 1994-2011 World Wide Web Consortium
 * See http://www.w3.org/Consortium/Legal/copyright-software
 *
 * Author: Bert Bos <bert@w3.org>
 * Created: 12 May 1998
 **/

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
#include "export.h"

EXPORT u_short portbase = 0;			/* for non-root servers */


/* connectsock -- allocate & connect a socket using TCP or UDP */
EXPORT int connectsock(const char *host, const char *service, char *protocol)
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
EXPORT int connectTCP(const char *host, const char *service)
{
  return connectsock(host, service, "tcp");
}

/* connectUDP -- connect to a specified UDP service on a specified host */
EXPORT int connectUDP(char *host, char *service)
{
  return connectsock(host, service, "udp");
}

/* passivesock -- allocate & bind a server socket using TCP or UDP */
EXPORT int passivesock(char *service, char *protocol, int qlen)
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

/* passiveTCP -- creat a passive socket for use in a TCP server */
EXPORT int passiveTCP(char *service, int qlen)
{
  /* service = service associated with the desired port		*/
  /* qlen = maximum server request queue length			*/
  return passivesock(service, "tcp", qlen);
}

/* passiveUDP -- creat a passive socket for use in a UDP server */
EXPORT int passiveUDP(char *service)
{
  return passivesock(service, "udp", 0);
}
