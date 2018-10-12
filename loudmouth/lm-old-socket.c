/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2006-2008 Imendio AB
 * Copyright (C) 2006 Nokia Corporation. All rights reserved.
 * Copyright (C) 2007 Collabora Ltd.
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
 * License along with this program; if not, see <https://www.gnu.org/licenses>
 */

#include <config.h>

#include <errno.h>
#include <string.h>
#include <sys/types.h>

/* Needed on Mac OS X */
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

/* Needed on Mac OS X */
#if HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "lm-debug.h"
#include "lm-error.h"
#include "lm-internals.h"
#include "lm-misc.h"
#include "lm-proxy.h"
#include "lm-resolver.h"
#include "lm-ssl.h"
#include "lm-ssl-internals.h"
#include "lm-sock.h"
#include "lm-old-socket.h"

#define IN_BUFFER_SIZE 1024
#define SRV_LEN 8192

struct _LmOldSocket {
    LmConnection      *connection;
    GMainContext      *context;

    gchar             *domain;
    gchar             *server;
    guint              port;

    LmSSL             *ssl;
    gboolean           ssl_started;
    LmProxy           *proxy;

    GIOChannel        *io_channel;
    GSource           *watch_in;
    GSource           *watch_err;
    GSource           *watch_hup;

    LmOldSocketT       fd;

    GSource           *watch_connect;

    gboolean           cancel_open;

    GSource           *watch_out;
    GString           *out_buf;

    LmConnectData     *connect_data;

    IncomingDataFunc   data_func;
    SocketClosedFunc   closed_func;
    ConnectResultFunc  connect_func;
    gpointer           user_data;

    guint              ref_count;

    LmResolver        *resolver;
};

static void         socket_free                    (LmOldSocket    *socket);
static gboolean     socket_do_connect              (LmConnectData  *connect_data);
static gboolean     socket_connect_cb              (GIOChannel     *source,
                                                    GIOCondition    condition,
                                                    LmConnectData  *connect_data);
static gboolean     socket_in_event                (GIOChannel     *source,
                                                    GIOCondition    condition,
                                                    LmOldSocket    *socket);
static gboolean     socket_hup_event               (GIOChannel     *source,
                                                    GIOCondition    condition,
                                                    LmOldSocket    *socket);
static gboolean     socket_error_event             (GIOChannel     *source,
                                                    GIOCondition    condition,
                                                    LmOldSocket    *socket);
static gboolean     socket_buffered_write_cb       (GIOChannel     *source,
                                                    GIOCondition    condition,
                                                    LmOldSocket    *socket);
static void         socket_close_io_channel        (GIOChannel     *io_channel);
static gboolean     old_socket_output_is_buffered  (LmOldSocket    *socket,
                                                    const gchar    *buffer,
                                                    gint            len);
static void         old_socket_setup_output_buffer (LmOldSocket    *socket,
                                                    const gchar    *buffer,
                                                    gint            len);

static void
socket_free (LmOldSocket *socket)
{
    g_free (socket->server);
    g_free (socket->domain);

    if (socket->ssl) {
        lm_ssl_unref (socket->ssl);
    }

    if (socket->proxy) {
        lm_proxy_unref (socket->proxy);
    }

    if (socket->out_buf) {
        g_string_free (socket->out_buf, TRUE);
    }

    if (socket->resolver) {
        g_object_unref (socket->resolver);
    }

    g_free (socket);
}

static gint
old_socket_do_write (LmOldSocket *socket, const gchar *buf, guint len)
{
    gint b_written;

    if (socket->ssl_started) {
        b_written = _lm_ssl_send (socket->ssl, buf, len);
    } else {
        GIOStatus io_status = G_IO_STATUS_AGAIN;
        gsize     bytes_written;

        while (io_status == G_IO_STATUS_AGAIN) {
            io_status = g_io_channel_write_chars (socket->io_channel,
                                                  buf, len,
                                                  &bytes_written,
                                                  NULL);
        }

        b_written = bytes_written;

        if (io_status != G_IO_STATUS_NORMAL) {
            b_written = -1;
        }
    }

    return b_written;
}

gint
lm_old_socket_write (LmOldSocket *socket, const gchar *buf, gint len)
{
    gint b_written;

    if (old_socket_output_is_buffered (socket, buf, len)) {
        return len;
    }

    b_written = old_socket_do_write (socket, buf, len);

    if (b_written < len && b_written != -1) {
        old_socket_setup_output_buffer (socket,
                                        buf + b_written,
                                        len - b_written);
        return len;
    }

    return b_written;
}

static gboolean
socket_read_incoming (LmOldSocket *socket,
                      gchar    *buf,
                      gsize     buf_size,
                      gsize    *bytes_read,
                      gboolean *hangup,
                      gint     *reason)
{
    GIOStatus status;

    *hangup = FALSE;

    if (socket->ssl_started) {
        status = _lm_ssl_read (socket->ssl,
                               buf, buf_size - 1, bytes_read);
    } else {
        status = g_io_channel_read_chars (socket->io_channel,
                                          buf, buf_size - 1,
                                          bytes_read,
                                          NULL);
    }

    if (status != G_IO_STATUS_NORMAL) {
        switch (status) {
        case G_IO_STATUS_EOF:
            *reason = LM_DISCONNECT_REASON_HUP;
            break;
        case G_IO_STATUS_AGAIN:
            /* No data readable but we didn't hangup */
            return FALSE;
            break;
        case G_IO_STATUS_ERROR:
            *reason = LM_DISCONNECT_REASON_ERROR;
            break;
        default:
            *reason = LM_DISCONNECT_REASON_UNKNOWN;
        }

        /* Notify connection_in_event that we hangup the connection */
        *hangup = TRUE;

        return FALSE;
    }

    buf[*bytes_read] = '\0';

    /* There is more data to be read */
    return TRUE;
}

static gboolean
socket_in_event (GIOChannel   *source,
                 GIOCondition  condition,
                 LmOldSocket     *socket)
{
    gchar    buf[IN_BUFFER_SIZE];
    gsize    bytes_read = 0;
    gboolean read_anything = FALSE;
    gboolean hangup = 0;
    gint     reason = 0;

    if (!socket->io_channel) {
        return FALSE;
    }

    while (socket_read_incoming (socket, buf, IN_BUFFER_SIZE,
                                 &bytes_read, &hangup, &reason)) {

        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_NET, "\nRECV [%d]:\n",
               (int)bytes_read);
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_NET,
               "-----------------------------------\n");
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_NET, "'%s'\n", buf);
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_NET,
               "-----------------------------------\n");

        lm_verbose ("Read: %d chars\n", (int)bytes_read);

        (socket->data_func) (socket, buf, socket->user_data);

        read_anything = TRUE;
    }

    /* If we have read something, delay the hangup so that the data can be
     * processed. */
    if (hangup && !read_anything) {
        (socket->closed_func) (socket, reason, socket->user_data);
        return FALSE;
    }

    return TRUE;
}

static gboolean
socket_hup_event (GIOChannel   *source,
                  GIOCondition  condition,
                  LmOldSocket     *socket)
{
    lm_verbose ("HUP event: %d->'%s'\n",
                condition, lm_misc_io_condition_to_str (condition));

    if (!socket->io_channel) {
        return FALSE;
    }

    (socket->closed_func) (socket, LM_DISCONNECT_REASON_HUP,
                           socket->user_data);

    return TRUE;
}

static gboolean
socket_error_event (GIOChannel   *source,
                    GIOCondition  condition,
                    LmOldSocket     *socket)
{
    lm_verbose ("ERROR event: %d->'%s'\n",
                condition, lm_misc_io_condition_to_str (condition));

    if (!socket->io_channel) {
        return FALSE;
    }

    (socket->closed_func) (socket, LM_DISCONNECT_REASON_ERROR,
                           socket->user_data);

    return TRUE;
}

static gboolean
_lm_old_socket_ssl_init (LmOldSocket *socket, gboolean delayed)
{
    GError *error = NULL;
    const gchar *ssl_verify_domain = NULL;

    lm_verbose ("Setting up SSL...\n");

    _lm_ssl_initialize (socket->ssl);

#ifdef HAVE_GNUTLS
    /* GNU TLS requires the socket to be blocking */
    _lm_sock_set_blocking (socket->fd, TRUE);
#endif

    /* If we're using StartTLS, the correct thing is to verify against
     * the domain. If we're using old SSL, we should verify against the
     * hostname. */
    if (delayed)
        ssl_verify_domain = socket->domain;
    else
        ssl_verify_domain = socket->server;

    if (!_lm_ssl_begin (socket->ssl, socket->fd, ssl_verify_domain, &error)) {
        lm_verbose ("Could not begin SSL\n");

        if (error) {
            g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_NET,
                   "%s\n", error->message);
            g_error_free (error);
        }

        _lm_sock_shutdown (socket->fd);
        _lm_sock_close (socket->fd);

        if (!delayed && socket->connect_func) {
            (socket->connect_func) (socket, FALSE, socket->user_data);
        }

        return FALSE;
    }

#ifdef HAVE_GNUTLS
    _lm_sock_set_blocking (socket->fd, FALSE);
#endif

    socket->ssl_started = TRUE;

    return TRUE;
}

gboolean
lm_old_socket_starttls (LmOldSocket *socket)
{
    g_return_val_if_fail (lm_ssl_get_use_starttls (socket->ssl) == TRUE, FALSE);

    return _lm_old_socket_ssl_init (socket, TRUE);
}



void
_lm_old_socket_succeeded (LmConnectData *connect_data)
{
    LmOldSocket *socket;

    socket = connect_data->socket;

    if (socket->watch_connect) {
        g_source_destroy (socket->watch_connect);
        socket->watch_connect = NULL;
    }

    /* Need some way to report error/success */
    if (socket->cancel_open) {
        lm_verbose ("Cancelling connection...\n");
        if (socket->connect_func) {
            (socket->connect_func) (socket, FALSE, socket->user_data);
        }
        return;
    }

    socket->fd = connect_data->fd;
    socket->io_channel = connect_data->io_channel;

    g_object_unref (socket->resolver);
    socket->resolver = NULL;

    socket->connect_data = NULL;
    g_free (connect_data);

    /* old-style ssl should be started immediately */
    if (socket->ssl && (lm_ssl_get_use_starttls (socket->ssl) == FALSE)) {
        if (!_lm_old_socket_ssl_init (socket, FALSE)) {
            return;
        }
    }

    socket->watch_in =
        lm_misc_add_io_watch (socket->context,
                              socket->io_channel,
                              G_IO_IN,
                              (GIOFunc) socket_in_event,
                              socket);

    /* FIXME: if we add these, we don't get ANY
     * response from the server, this is to do with the way that
     * windows handles watches, see bug #331214.
     */
#ifndef G_OS_WIN32
    socket->watch_err =
        lm_misc_add_io_watch (socket->context,
                              socket->io_channel,
                              G_IO_ERR,
                              (GIOFunc) socket_error_event,
                              socket);

    socket->watch_hup =
        lm_misc_add_io_watch (socket->context,
                              socket->io_channel,
                              G_IO_HUP,
                              (GIOFunc) socket_hup_event,
                              socket);
#endif

    if (socket->connect_func) {
        (socket->connect_func) (socket, TRUE, socket->user_data);
    }
}

gboolean
_lm_old_socket_failed_with_error (LmConnectData *connect_data, int error)
{
    LmOldSocket *socket;

    g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_NET,
           "Connection failed: %s (error %d)\n",
           _lm_sock_get_error_str (error), error);

    socket = lm_old_socket_ref (connect_data->socket);

    connect_data->current_addr = lm_resolver_results_get_next (socket->resolver);

    if (socket->watch_connect) {
        g_source_destroy (socket->watch_connect);
        socket->watch_connect = NULL;
    }

    if (connect_data->io_channel != NULL) {
        socket_close_io_channel (connect_data->io_channel);
        connect_data->io_channel = NULL;
    }

    if (connect_data->current_addr == NULL) { /*Ran Out Of Addresses*/
        if (socket->connect_func) {
            (socket->connect_func) (socket, FALSE, socket->user_data);
        }

        /* if the user callback called connection_close(), this is already freed */
        if (socket->connect_data != NULL) {
            if (socket->resolver) {
                g_object_unref (socket->resolver);
            }

            socket->connect_data = NULL;
            g_free (connect_data);
        }
    } else {
        /* try to connect to the next host */
        return socket_do_connect (connect_data);
    }

    lm_old_socket_unref (socket);

    return FALSE;
}

gboolean
_lm_old_socket_failed (LmConnectData *connect_data)
{
    return _lm_old_socket_failed_with_error (connect_data,
                                             _lm_sock_get_last_error());
}

static gboolean
socket_connect_cb (GIOChannel   *source,
                   GIOCondition  condition,
                   LmConnectData *connect_data)
{
    LmOldSocket     *socket;
    /* struct addrinfo *addr; */
    int              err;
    socklen_t        len;
    LmOldSocketT     fd;
    gboolean         result = FALSE;

    socket = lm_old_socket_ref (connect_data->socket);
    /* addr = connect_data->current_addr; */
    fd = g_io_channel_unix_get_fd (source);

    if (condition & G_IO_ERR) {
        len = sizeof (err);
        _lm_sock_get_error (fd, &err, &len);
        if (!_lm_sock_is_blocking_error (err)) {
            g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_VERBOSE,
                   "Connection failed.\n");

            /* error condition, but might be possible to recover
             * from it (by connecting to the next host) */
            if (!_lm_old_socket_failed_with_error (connect_data, err)) {
                socket->watch_connect = NULL;
            }
            goto out;
        }
    }

#if 0
    if (_lm_connection_async_connect_waiting (socket->connection)) {
        gint res;

        fd = g_io_channel_unix_get_fd (source);

        res = _lm_sock_connect (fd, addr->ai_addr, (int)addr->ai_addrlen);
        if (res < 0) {
            err = _lm_sock_get_last_error ();
            if (_lm_sock_is_blocking_success (err)) {
                _lm_connection_set_async_connect_waiting (socket->connection, FALSE);

                g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_NET,
                       "Connection success (1).\n");

                _lm_old_socket_succeeded (connect_data);
            }

            if (_lm_connection_async_connect_waiting (socket->connection) &&
                !_lm_sock_is_blocking_error (err)) {
                g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_NET,
                       "Connection failed.\n");

                _lm_sock_close (connect_data->fd);
                _lm_old_socket_failed_with_error (connect_data, err);

                socket->watch_connect = NULL;
                goto out;
            }
        }
    } else {
#endif
    {
        /* for blocking sockets, G_IO_OUT means we are connected */
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_VERBOSE,
               "Connection success (2).\n");

        _lm_old_socket_succeeded (connect_data);
    }

    result = TRUE;

 out:
    lm_old_socket_unref(socket);

    return result;
}

static gboolean
socket_do_connect (LmConnectData *connect_data)
{
    LmOldSocket     *socket;
    LmOldSocketT     fd;
    int              res, err;
    int              port;
    char             name[NI_MAXHOST];
    char             portname[NI_MAXSERV];
    struct addrinfo *addr;

    socket = connect_data->socket;
    addr = connect_data->current_addr;

    if (socket->port == 0) {
        socket->port = 5222;
    }

    if (socket->proxy) {
        port = htons (lm_proxy_get_port (socket->proxy));
    } else {
        port = htons (socket->port);
    }

    switch (addr->ai_family) {
    case AF_INET:
        ((struct sockaddr_in *) addr->ai_addr)->sin_port = port;
        break;
    case AF_INET6:
        ((struct sockaddr_in6 *) addr->ai_addr)->sin6_port = port;
        break;
    default:
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_VERBOSE,
               "Unknown socket family %d\n", addr->ai_family);
#ifndef G_OS_WIN32
        return _lm_old_socket_failed_with_error (connect_data, EAFNOSUPPORT);
#else
        return _lm_old_socket_failed_with_error (connect_data, WSAEAFNOSUPPORT);
#endif
    }

    res = getnameinfo (addr->ai_addr,
                       (socklen_t)addr->ai_addrlen,
                       name,     sizeof (name),
                       portname, sizeof (portname),
                       NI_NUMERICHOST | NI_NUMERICSERV);

    if (res < 0) {
        return _lm_old_socket_failed (connect_data);
    }

    g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_NET,
           "Trying %s port %s...\n", name, portname);

    fd = _lm_sock_makesocket (addr->ai_family,
                              addr->ai_socktype,
                              addr->ai_protocol);

    if (!_LM_SOCK_VALID (fd)) {
        g_print("invalid fd\n");
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_NET,
               "Failed making socket, error:%d...\n",
               _lm_sock_get_last_error ());

        return _lm_old_socket_failed (connect_data);
    }

    /* Even though it says _unix_new(), it is supported by glib on
     * win32 because glib does some cool stuff to find out if it
     * can treat it as a FD or a windows SOCKET.
     */
    connect_data->fd = fd;
    connect_data->io_channel = g_io_channel_unix_new (fd);

    g_io_channel_set_encoding (connect_data->io_channel, NULL, NULL);
    g_io_channel_set_buffered (connect_data->io_channel, FALSE);

    _lm_sock_set_blocking (connect_data->fd, FALSE);

    if (socket->proxy) {
        socket->watch_connect =
            lm_misc_add_io_watch (socket->context,
                                  connect_data->io_channel,
                                  G_IO_OUT|G_IO_ERR,
                                  (GIOFunc) _lm_proxy_connect_cb,
                                  connect_data);
    } else {
        socket->watch_connect =
            lm_misc_add_io_watch (socket->context,
                                  connect_data->io_channel,
                                  G_IO_OUT|G_IO_ERR,
                                  (GIOFunc) socket_connect_cb,
                                  connect_data);
    }

    res = _lm_sock_connect (connect_data->fd,
                            addr->ai_addr, (int)addr->ai_addrlen);
    if (res < 0) {
        err = _lm_sock_get_last_error ();
        if (!_lm_sock_is_blocking_error (err)) {
            _lm_sock_close (connect_data->fd);
            g_print("unable to connect\n");
            return _lm_old_socket_failed_with_error (connect_data, err);
        }
    }

    return TRUE;
}

static gboolean
old_socket_output_is_buffered (LmOldSocket     *socket,
                               const gchar  *buffer,
                               gint          len)
{
    if (socket->out_buf) {
        lm_verbose ("Appending %d bytes to output buffer\n", len);
        g_string_append_len (socket->out_buf, buffer, len);
        return TRUE;
    }

    return FALSE;
}

static void
old_socket_setup_output_buffer (LmOldSocket *socket, const gchar *buffer, gint len)
{
    lm_verbose ("OUTPUT BUFFER ENABLED\n");

    socket->out_buf = g_string_new_len (buffer, len);

    socket->watch_out =
        lm_misc_add_io_watch (socket->context,
                              socket->io_channel,
                              G_IO_OUT,
                              (GIOFunc) socket_buffered_write_cb,
                              socket);
}

static gboolean
socket_buffered_write_cb (GIOChannel   *source,
                          GIOCondition  condition,
                          LmOldSocket     *socket)
{
    gint     b_written;
    GString *out_buf;

    out_buf = socket->out_buf;
    if (!out_buf) {
        /* Should not be possible */
        return FALSE;
    }

    b_written = old_socket_do_write (socket, out_buf->str, out_buf->len);

    if (b_written < 0) {
        (socket->closed_func) (socket, LM_DISCONNECT_REASON_ERROR,
                               socket->user_data);
        return FALSE;
    }

    g_string_erase (out_buf, 0, (gsize) b_written);
    if (out_buf->len == 0) {
        lm_verbose ("Output buffer is empty, going back to normal output\n");

        if (socket->watch_out) {
            g_source_destroy (socket->watch_out);
            socket->watch_out = NULL;
        }

        g_string_free (out_buf, TRUE);
        socket->out_buf = NULL;
        return FALSE;
    }

    return TRUE;
}

static void
socket_close_io_channel (GIOChannel *io_channel)
{
    gint fd;

    g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_NET,
           "Freeing up IOChannel and file descriptor\n");

    fd = g_io_channel_unix_get_fd (io_channel);

    g_io_channel_unref (io_channel);

    _lm_sock_close (fd);
}

static void
old_socket_resolver_host_cb (LmResolver       *resolver,
                             LmResolverResult  result,
                             gpointer          user_data)
{
    LmOldSocket *socket = (LmOldSocket *) user_data;
    char dispbuf[128];
    struct addrinfo *addr;
    void *sock_addr;

    lm_verbose ("LmOldSocket::host_cb (result=%d)\n", result);

    if (result == LM_RESOLVER_RESULT_OK) {
        /* Find and use the first result with a supported address family */
        while ((addr = lm_resolver_results_get_next (resolver))) {
            switch (addr->ai_family) {
            case AF_INET:
                sock_addr = & (((struct sockaddr_in *) addr->ai_addr)->sin_addr);
                break;
            case AF_INET6:
                sock_addr = & (((struct sockaddr_in6 *) addr->ai_addr)->sin6_addr);
                break;
            default:
                g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_VERBOSE,
                       "Resolver returned a socket address with unknown family %d\n", addr->ai_family);
                continue;
            }
            if (inet_ntop (addr->ai_family, sock_addr, dispbuf, sizeof(dispbuf))) {
                g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_VERBOSE,
                       "Attempting Connection to %s\n", dispbuf);
            } else {
                g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_VERBOSE,
                       "Attempting Connection (unable to convert address to presentable format)\n");
            };
            socket->connect_data->current_addr = addr;
            socket_do_connect (socket->connect_data);
            return;
        }
    }

    lm_verbose ("error while resolving, bailing out\n");
    if (socket->connect_func) {
        (socket->connect_func) (socket, FALSE, socket->user_data);
    }
    /*FIXME: Leaking Resolvers Until Clean Up Can Be Properly Handled
    g_object_unref (socket->resolver);
    socket->resolver = NULL;*/
    g_free (socket->connect_data);
    socket->connect_data = NULL;
}

/* FIXME: Need to have a way to only get srv reply and then decide if the
 *        resolver should continue to look the host up.
 *
 *        This is needed for the case when we do a SRV lookup to lookup the
 *        real host of the service and then connect to it through a proxy.
 */
static void
old_socket_resolver_srv_cb (LmResolver       *resolver,
                            LmResolverResult  result,
                            gpointer          user_data)
{
    LmOldSocket *socket = (LmOldSocket *) user_data;
    const gchar *remote_addr;

    lm_verbose ("LmOldSocket::srv_cb (result=%d)\n", result);

    if (result != LM_RESOLVER_RESULT_OK) {
        lm_verbose ("SRV lookup failed, trying jid domain\n");
        socket->server = g_strdup (socket->domain);
    } else {
        g_object_get (resolver, "host", &socket->server, NULL);
        g_object_get (resolver, "port", &socket->port, NULL);
    }

    if (socket->proxy) {
        remote_addr = lm_proxy_get_server (socket->proxy);
    } else if (socket->server) {
        remote_addr = socket->server;
    }
    else {
        remote_addr = socket->domain;
    }

    g_object_unref (socket->resolver);

    socket->resolver =
            lm_resolver_new_for_host (remote_addr,
                                      old_socket_resolver_host_cb,
                                      socket);

    lm_resolver_lookup (socket->resolver);
}

LmOldSocket *
lm_old_socket_create (GMainContext      *context,
                      IncomingDataFunc   data_func,
                      SocketClosedFunc   closed_func,
                      ConnectResultFunc  connect_func,
                      gpointer           user_data,
                      LmConnection      *connection,
                      const gchar       *server,
                      const gchar       *domain,
                      guint              port,
                      LmSSL             *ssl,
                      LmProxy           *proxy,
                      GError           **error)
{
    LmOldSocket   *socket;
    LmConnectData *data;

    g_return_val_if_fail (domain != NULL, NULL);
    g_return_val_if_fail ((port >= LM_MIN_PORT && port <= LM_MAX_PORT), NULL);
    g_return_val_if_fail (data_func != NULL, NULL);
    g_return_val_if_fail (closed_func != NULL, NULL);
    g_return_val_if_fail (connect_func != NULL, NULL);

    socket = g_new0 (LmOldSocket, 1);

    socket->ref_count = 1;

    socket->connection = connection;
    socket->domain = g_strdup (domain);
    socket->server = g_strdup (server);
    socket->port = port;
    socket->cancel_open = FALSE;
    socket->ssl = ssl;
    socket->ssl_started = FALSE;
    socket->proxy = NULL;

    if (context) {
        socket->context = g_main_context_ref (context);
    }

    if (proxy) {
        socket->proxy = lm_proxy_ref (proxy);
    }

    data = g_new0 (LmConnectData, 1);
    data->socket = socket;
    data->connection = socket->connection;
    data->fd = -1;
    socket->connect_data = data;

    if (!server) {
        socket->resolver = lm_resolver_new_for_service (socket->domain,
                                                        "xmpp-client",
                                                        "tcp",
                                                        old_socket_resolver_srv_cb,
                                                        socket);
    } else {
        socket->resolver =
            lm_resolver_new_for_host (socket->server ? socket->server : socket->domain,
                                      old_socket_resolver_host_cb,
                                      socket);
    }

    if (socket->context) {
        g_object_set (socket->resolver, "context", context, NULL);
    }

    socket->data_func = data_func;
    socket->closed_func = closed_func;
    socket->connect_func = connect_func;
    socket->user_data = user_data;

    lm_resolver_lookup (socket->resolver);

    return socket;
}

void
lm_old_socket_flush (LmOldSocket *socket)
{
    g_return_if_fail (socket != NULL);
    g_return_if_fail (socket->io_channel != NULL);

    g_io_channel_flush (socket->io_channel, NULL);
}

void
lm_old_socket_close (LmOldSocket *socket)
{
    LmConnectData *data;

    g_return_if_fail (socket != NULL);

    if (socket->watch_connect) {
        g_source_destroy (socket->watch_connect);
        socket->watch_connect = NULL;
    }

    data = socket->connect_data;
    if (data) {
        if (data->io_channel) {
            socket_close_io_channel (data->io_channel);
        }
        socket->connect_data = NULL;
        g_free (data);
    }

    /* FIXME: Leaking Resolvers Until Clean Up Can Be Corrected
    if (socket->resolver) {
        g_object_unref (socket->resolver);
        socket->resolver = NULL;
    } */

    if (socket->io_channel) {
        if (socket->watch_in) {
            g_source_destroy (socket->watch_in);
            socket->watch_in = NULL;
        }

        if (socket->watch_err) {
            g_source_destroy (socket->watch_err);
            socket->watch_err = NULL;
        }

        if (socket->watch_hup) {
            g_source_destroy (socket->watch_hup);
            socket->watch_hup = NULL;
        }

        if (socket->watch_out) {
            g_source_destroy (socket->watch_out);
            socket->watch_out = NULL;
        }

        socket_close_io_channel (socket->io_channel);

        socket->io_channel = NULL;
        socket->fd = -1;
    }

    if (socket->ssl) {
        _lm_ssl_close (socket->ssl);
    }
}

gchar *
lm_old_socket_get_local_host (LmOldSocket *socket)
{
    return _lm_sock_get_local_host (socket->fd);
}

LmOldSocket *
lm_old_socket_ref (LmOldSocket *socket)
{
    g_return_val_if_fail (socket != NULL, NULL);

    socket->ref_count++;

    return socket;
}

void
lm_old_socket_unref (LmOldSocket *socket)
{
    g_return_if_fail (socket != NULL);

    socket->ref_count--;

    if (socket->ref_count <= 0) {
        socket_free (socket);
    }
}

gboolean
lm_old_socket_set_keepalive (LmOldSocket *socket, int delay)
{
#ifdef USE_TCP_KEEPALIVES
    return _lm_sock_set_keepalive (socket->fd, delay);
#else
    return FALSE;
#endif /* USE_TCP_KEEPALIVES */
}

void
lm_old_socket_asyncns_cancel (LmOldSocket *socket)
{
    if (!socket->resolver) {
        return;
    }

    lm_resolver_cancel (socket->resolver);
}

gboolean
lm_old_socket_get_use_starttls (LmOldSocket *socket)
{
    if (!socket->ssl) {
        return FALSE;
    }

    return lm_ssl_get_use_starttls (socket->ssl);
}

gboolean
lm_old_socket_get_require_starttls (LmOldSocket *socket)
{
    if (!socket->ssl) {
        return FALSE;
    }

    return lm_ssl_get_require_starttls (socket->ssl);
}
