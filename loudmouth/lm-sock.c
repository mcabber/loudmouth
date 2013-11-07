/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2006 Imendio AB
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <config.h>

#include <glib.h>
#include <glib/gi18n.h>

#ifndef G_OS_WIN32

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>

/* Needed for BSD, LM-130 */
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>
#define LM_SHUTDOWN SHUT_RDWR

#else  /* G_OS_WIN32 */

#include <winsock2.h>
#define LM_SHUTDOWN SD_BOTH

#endif /* G_OS_WIN32 */

#include "lm-internals.h"
#include "lm-connection.h"
#include "lm-sock.h"
#include "lm-debug.h"

#define IPV6_MAX_ADDRESS_LEN 46 /* 45 + '\0' */

static gboolean initialised = FALSE;

gboolean
_lm_sock_library_init (void)
{
#ifdef G_OS_WIN32
    WORD    version;
    WSADATA data;
    int     error;
#endif /* G_OS_WIN32 */

    if (initialised) {
        return TRUE;
    }

    lm_verbose ("Socket library initialising...\n");

#ifdef G_OS_WIN32
    lm_verbose ("Checking for winsock 2.0 or above...\n");

    version = MAKEWORD (2, 0);

    error = WSAStartup (version, &data);
    if (error != 0) {
        g_printerr ("WSAStartup() failed, error:%d\n", error);
        return FALSE;
    }

    /* Confirm that the WinSock DLL supports 2.0.
     * Note that if the DLL supports versions greater
     * than 2.0 in addition to 2.0, it will still return
     * 2.0 in wVersion since that is the version we
     * requested.
     */
    if (LOBYTE (data.wVersion) != 2 ||
        HIBYTE (data.wVersion) != 0) {
        /* Tell the user that we could not find a usable
         * WinSock DLL.
         */
        g_printerr ("Socket library version is not sufficient!\n");
        WSACleanup ();
        return FALSE;
    }
#endif /* G_OS_WIN32 */

    initialised = TRUE;

    return TRUE;
}

void
_lm_sock_library_shutdown (void)
{
    if (!initialised) {
        return;
    }

    lm_verbose ("Socket library shutting down...\n");

#ifdef G_OS_WIN32
    WSACleanup ();
#endif /* G_OS_WIN32 */

    initialised = FALSE;
}

void
_lm_sock_set_blocking (LmOldSocketT sock,
                       gboolean block)
{
    int res;

#ifndef G_OS_WIN32
    res = fcntl (sock, F_SETFL, block ? 0 : O_NONBLOCK);
#else  /* G_OS_WIN32 */
    u_long mode = (block ? 0 : 1);
    res = ioctlsocket (sock, FIONBIO, &mode);
#endif /* G_OS_WIN32 */

    if (res != 0) {
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_NET,
               "Could not set connection to be %s\n",
               block ? "blocking" : "non-blocking");
    }
}

void
_lm_sock_shutdown (LmOldSocketT sock)
{
    shutdown (sock, LM_SHUTDOWN);
}

void
_lm_sock_close (LmOldSocketT sock)
{
#ifndef G_OS_WIN32
    close (sock);
#else  /* G_OS_WIN32 */
    closesocket (sock);
#endif /* G_OS_WIN32 */
}

LmOldSocketT
_lm_sock_makesocket (int af,
                     int type,
                     int protocol)
{
    return (LmOldSocketT)socket (af, type, protocol);
}

int
_lm_sock_connect (LmOldSocketT          sock,
                  const struct sockaddr *name,
                  int                   namelen)
{
    return connect (sock, name, namelen);
}

gboolean
_lm_sock_is_blocking_error (int err)
{
#ifndef G_OS_WIN32
    return (err == _LM_SOCK_EINPROGRESS);
#else  /* G_OS_WIN32 */
    return (err == _LM_SOCK_EINPROGRESS ||
            err == _LM_SOCK_EWOULDBLOCK ||
            err == _LM_SOCK_EINVAL);
#endif /* G_OS_WIN32 */
}

gboolean
_lm_sock_is_blocking_success (int err)
{
    return (err == _LM_SOCK_EALREADY || err == _LM_SOCK_EISCONN);
}

int
_lm_sock_get_last_error (void)
{
#ifndef G_OS_WIN32
    return errno;
#else  /* G_OS_WIN32 */
    return WSAGetLastError ();
#endif /* G_OS_WIN32 */
}

void
_lm_sock_get_error (LmOldSocketT   sock,
                    void      *error,
                    socklen_t *len)
{
    if (getsockopt (sock, SOL_SOCKET, SO_ERROR, (void*) error, len) != 0)
	*((int *) error) = errno;
}

const gchar *
_lm_sock_get_error_str (int err)
{
#ifndef G_OS_WIN32
    return strerror (err);
#else  /* G_OS_WIN32 */
    switch (err) {
    case WSAEINTR:              return _("Connect interrupted and canceled");
    case WSAEACCES:             return _("Permission denied");
    case WSAEFAULT:             return _("Bad address");
    case WSAEINVAL:             return _("Invalid argument");
    case WSAEMFILE:             return _("Too many open sockets");
    case WSAEWOULDBLOCK:        return _("Resource temporarily unavailable");
    case WSAEINPROGRESS:        return _("Operation now in progress");
    case WSAEALREADY:           return _("Operation already in progress");
    case WSAENOTSOCK:           return _("Socket operation on nonsocket");
    case WSAEDESTADDRREQ:       return _("Destination address required");
    case WSAEMSGSIZE:           return _("Message too long");
    case WSAEPROTOTYPE:         return _("Protocol wrong type for socket");
    case WSAENOPROTOOPT:        return _("Bad protocol option");
    case WSAEPROTONOSUPPORT:    return _("Protocol not supported");
    case WSAESOCKTNOSUPPORT:    return _("Socket type not supported");
    case WSAEOPNOTSUPP:         return _("Operation not supported");
    case WSAEPFNOSUPPORT:       return _("Protocol family not supported");
    case WSAEAFNOSUPPORT:       return _("Address family not supported by protocol family");
    case WSAEADDRINUSE:         return _("Address already in use");
    case WSAEADDRNOTAVAIL:      return _("Can not assign requested address");
    case WSAENETDOWN:           return _("Network is down");
    case WSAENETUNREACH:        return _("Network is unreachable");
    case WSAENETRESET:          return _("Network dropped connection on reset");
    case WSAECONNABORTED:       return _("Software caused connection abort");
    case WSAECONNRESET:         return _("Connection reset by peer");
    case WSAENOBUFS:            return _("No buffer space available");
    case WSAEISCONN:            return _("Socket is already connected");
    case WSAENOTCONN:           return _("Socket is not connected");
    case WSAESHUTDOWN:          return _("Can not send after socket shutdown");
    case WSAETIMEDOUT:          return _("Connection timed out");
    case WSAECONNREFUSED:       return _("Connection refused");
    case WSAEHOSTDOWN:          return _("Host is down");
    case WSAEHOSTUNREACH:       return _("No route to host");
    case WSAEPROCLIM:           return _("Too many processes");
    case WSASYSNOTREADY:        return _("Network subsystem is unavailable");
    case WSAVERNOTSUPPORTED:    return _("Winsock library version is out of range ");
    case WSANOTINITIALISED:     return _("Successful WSAStartup not yet performed");
    case WSAEDISCON:            return _("Graceful shutdown in progress");
    case WSATYPE_NOT_FOUND:     return _("Class type not found");
    case WSAHOST_NOT_FOUND:     return _("Host not found");
    case WSATRY_AGAIN:          return _("Nonauthoritative host not found");
    case WSANO_RECOVERY:        return _("This is a nonrecoverable error");
    case WSANO_DATA:            return _("Valid name, no data record of requested type");
    case WSA_INVALID_HANDLE:    return _("Specified event object handle is invalid");
    case WSA_INVALID_PARAMETER: return _("One or more parameters are invalid");
    case WSA_IO_INCOMPLETE:     return _("Overlapped I/O event object no in signaled state");
    case WSA_IO_PENDING:        return _("Overlapped operations will complete later");
    case WSA_NOT_ENOUGH_MEMORY: return _("Insufficient memory available");
    case WSA_OPERATION_ABORTED: return _("Overlapped operation aborted");
        /* os dependent */
    case WSASYSCALLFAILURE:     return _("System call failure");
    }

    return _("Unknown");
#endif /* G_OS_WIN32 */
}

const gchar *
_lm_sock_addrinfo_get_error_str (int err)
{
    switch (err) {
    case EAI_AGAIN:
        return _("The nameserver failed to return an "
                 "address, try again later");
    case EAI_BADFLAGS:
        return _("Internal error trying to obtain remote address");
    case EAI_FAIL:
        return _("The nameserver encountered errors "
                 "looking up this address");
        /* EAI_NODATA is apparently missing on FreeBSD. On recent GNU libc,
         * it requires _GNU_SOURCE to be defined; in the unlikely case that
         * that GNU libc returns this value we'll return the default message */
#ifdef EAI_NODATA
    case EAI_NODATA:
        return _("The remote host exists but no address "
                 "is available");
#endif
    case EAI_NONAME:
        return _("The remote address is unknown");
    case EAI_FAMILY:
    case EAI_SERVICE:
    case EAI_SOCKTYPE:
        return _("The remote address is not obtainable "
                 "for that socket type.");
    default:
        break;
    }

    return _("The remote address could not be obtained ");
}

gboolean
_lm_sock_set_keepalive (LmOldSocketT sock, int delay)
{
#ifdef USE_TCP_KEEPALIVES

#ifdef __APPLE__
#ifndef TCP_KEEPIDLE
#define TCP_KEEPIDLE TCP_KEEPALIVE
#endif
#endif

    int opt;

    opt = 1;
    if (setsockopt (sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof (opt)) < 0) {
        return FALSE;
    }

    opt = 3; /* 3 keepalives before considering connection dead */
    if (setsockopt (sock, IPPROTO_TCP, TCP_KEEPCNT, &opt, sizeof (opt)) < 0) {
        return FALSE;
    }

    opt = delay;
    if (setsockopt (sock, IPPROTO_TCP, TCP_KEEPIDLE, &opt, sizeof (opt)) < 0) {
        return FALSE;
    }

    opt = delay;
    if (setsockopt (sock, IPPROTO_TCP, TCP_KEEPINTVL, &opt, sizeof (opt)) < 0) {
        return FALSE;
    }
#endif /* USE_TCP_KEEPALIVES */

    return TRUE;
}

gchar *
_lm_sock_get_local_host (LmOldSocketT sock)
{
    struct sockaddr      addr_info;
    void                *sock_addr;
    socklen_t            namelen;
    char                 addrbuf[IPV6_MAX_ADDRESS_LEN];
    const char          *host;

    namelen = sizeof (struct sockaddr);
    if (getsockname (sock, &addr_info, &namelen)) {
        return NULL;
    }

    switch (addr_info.sa_family) {
    case AF_INET:

        sock_addr = & (((struct sockaddr_in *) &addr_info)->sin_addr);
        break;
    case AF_INET6:
        sock_addr = & (((struct sockaddr_in6 *) &addr_info)->sin6_addr);
        break;
    default:
        return NULL;
    }
    /* inet_ntoa has been obsoleted in favour of inet_ntop */
    host = inet_ntop (addr_info.sa_family,
                      sock_addr,
                      addrbuf,
                      IPV6_MAX_ADDRESS_LEN);

    return g_strdup (host);
}
