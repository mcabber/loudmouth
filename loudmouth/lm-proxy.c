/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2004 Imendio AB
 * Copyright (C) 2004 Josh Beam <josh@3ddrome.com>
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

/**
 * SECTION:lm-proxy
 * @Title: LmProxy
 * @Short_description: API for the proxy support in Loudmouth
 *
 * Use this together with an #LmConnection to get the connection to use connect through a proxy. Example of how to use the #LmProxy API.
 * <informalexample><programlisting><![CDATA[
 * LmConnection *connection;
 * LmProxy      *proxy;
 *
 * connection = lm_connection_new ("myserver");
 * proxy = lm_proxy_new_with_server (LM_PROXY_TYPE_HTTP,
 *                "myproxyserver",
 *                8080);
 * lm_connection_set_proxy (connection, proxy);
 * ...]]></programlisting></informalexample>
 */

#include <config.h>

#include <glib.h>
#include <string.h>

#ifndef G_OS_WIN32

#include <unistd.h>
#include <sys/socket.h>

#else  /* G_OS_WIN32 */

#include <winsock2.h>

#endif /* G_OS_WIN32 */

#include "lm-internals.h"
#include "lm-proxy.h"
#include "lm-utils.h"

struct _LmProxy {
    LmProxyType  type;
    gchar       *server;
    guint        port;
    gchar       *username;
    gchar       *password;
    guint        io_watch;

    gint         ref_count;
};

static void          proxy_free              (LmProxy       *proxy);
static gboolean      proxy_http_negotiate    (LmProxy       *proxy,
                                              gint           fd,
                                              const gchar   *server,
                                              guint          port);
static gboolean      proxy_negotiate         (LmProxy       *proxy,
                                              gint           fd,
                                              const gchar   *server,
                                              guint          port);
static gboolean      proxy_http_read_cb      (GIOChannel    *source,
                                              GIOCondition   condition,
                                              gpointer       data);
static gboolean      proxy_read_cb           (GIOChannel    *source,
                                              GIOCondition   condition,
                                              gpointer       data);

static void
proxy_free (LmProxy *proxy)
{
    g_free (proxy->server);
    g_free (proxy->username);
    g_free (proxy->password);

    g_free (proxy);
}

static gboolean
proxy_http_negotiate (LmProxy *proxy, gint fd, const gchar *server, guint port)
{
    gchar *str;

    if (proxy->username && proxy->password) {
        gchar *tmp1;
        gchar *tmp2;

        tmp1 = g_strdup_printf ("%s:%s",
                                proxy->username,
                                proxy->password);
        tmp2 = g_base64_encode ((const guchar *) tmp1,
                                (gsize) strlen (tmp1));
        g_free (tmp1);

        str = g_strdup_printf ("CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\nProxy-Authorization: Basic %s\r\n\r\n",
                               server, port,
                               server, port,
                               tmp2);
        g_free (tmp2);
    } else {
        str = g_strdup_printf ("CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\n\r\n",
                               server, port,
                               server, port);
    }

    send (fd, str, strlen (str), 0);
    g_free (str);
    return TRUE;
}

/* returns TRUE when connected through proxy */
static gboolean
proxy_http_read_cb (GIOChannel *source, GIOCondition condition, gpointer data)
{
    gchar          buf[512];
    gsize          bytes_read;
    GError        *error = NULL;

    g_io_channel_read_chars (source, buf, 512, &bytes_read, &error);

    if (bytes_read < 16) {
        return FALSE;
    }

    if (strncmp (buf, "HTTP/1.1 200", 12) != 0 &&
        strncmp (buf, "HTTP/1.0 200", 12) != 0) {
        return FALSE;
    }

    if (strncmp (buf + (bytes_read - 4), "\r\n\r\n", 4) != 0) {
        return FALSE;
    }

    return TRUE;
}

static gboolean
proxy_read_cb (GIOChannel *source, GIOCondition condition, gpointer data)
{
    LmConnectData *connect_data;
    LmConnection  *connection;
    LmProxy       *proxy;
    gboolean       retval = FALSE;

    connect_data = (LmConnectData *) data;
    connection = connect_data->connection;
    proxy = lm_connection_get_proxy (connection);

    g_return_val_if_fail (proxy != NULL, FALSE);

    if (lm_connection_is_open (connection)) {
        return FALSE;
    }

    switch (lm_proxy_get_type (proxy)) {
    default:
    case LM_PROXY_TYPE_NONE:
        g_assert_not_reached ();
        break;
    case LM_PROXY_TYPE_HTTP:
        retval = proxy_http_read_cb (source, condition, data);
        break;
    }

    if (retval == TRUE) {
        g_source_remove (proxy->io_watch);
        _lm_old_socket_succeeded ((LmConnectData *) data);
    }

    return FALSE;
}

gboolean
proxy_negotiate (LmProxy *proxy, gint fd, const gchar *server, guint port)
{
    g_return_val_if_fail (proxy != NULL, FALSE);

    switch (proxy->type) {
    case LM_PROXY_TYPE_NONE:
        return TRUE;
    case LM_PROXY_TYPE_HTTP:
        return proxy_http_negotiate (proxy, fd, server, port);
    default:
        g_assert_not_reached ();
    }

    return FALSE;
}

gboolean
_lm_proxy_connect_cb (GIOChannel *source, GIOCondition condition, gpointer data)
{
    LmConnection  *connection;
    LmConnectData *connect_data;
    LmProxy       *proxy;
    int            error;
    socklen_t      len;

    connect_data = (LmConnectData *) data;
    connection = connect_data->connection;
    proxy = lm_connection_get_proxy (connection);

    g_return_val_if_fail (proxy != NULL, FALSE);

    if (condition & G_IO_ERR) {
        len = sizeof (error);
        _lm_sock_get_error (connect_data->fd, &error, &len);
        _lm_old_socket_failed_with_error (connect_data, error);
        return FALSE;
    } else if (condition & G_IO_OUT) {
        if (!proxy_negotiate (lm_connection_get_proxy (connection), connect_data->fd, lm_connection_get_server (connection), lm_connection_get_port (connection))) {
            _lm_old_socket_failed (connect_data);
            return FALSE;
        }

        proxy->io_watch = g_io_add_watch (connect_data->io_channel,
                                          G_IO_IN|G_IO_ERR,
                                          (GIOFunc) proxy_read_cb,
                                          connect_data);
    } else {
        g_assert_not_reached ();
    }

    return FALSE;
}

/**
 * lm_proxy_new
 * @type: the type of the new proxy
 *
 * Creates a new Proxy. Used #lm_connection_set_proxy to make a connection
 * user this proxy.
 *
 * Return value: a newly create proxy
 **/
LmProxy *
lm_proxy_new (LmProxyType type)
{
    LmProxy *proxy;

    proxy = g_new0 (LmProxy, 1);

    proxy->ref_count = 1;
    proxy->type = type;

    switch (proxy->type) {
    case LM_PROXY_TYPE_HTTP:
        proxy->port = 8000;
        break;
    default:
        proxy->port = 0;
    }

    return proxy;
}

/**
 * lm_proxy_new_with_server
 * @type: the type of the new proxy
 * @server: the proxy server
 * @port: the proxy server port
 *
 * Creates a new Proxy. Use #lm_connection_set_proxy to make a connection
 * user this proxy.
 *
 * Return value: a newly create proxy
 **/
LmProxy *
lm_proxy_new_with_server (LmProxyType  type,
                          const gchar *server,
                          guint        port)
{
    LmProxy *proxy;

    proxy = lm_proxy_new (type);
    lm_proxy_set_server (proxy, server);
    lm_proxy_set_port (proxy, port);

    return proxy;
}

/**
 * lm_proxy_get_type
 * @proxy: an #LmProxy
 *
 * Fetches the proxy type
 *
 * Return value: the type
 **/
LmProxyType
lm_proxy_get_type (LmProxy *proxy)
{
    g_return_val_if_fail (proxy != NULL, LM_PROXY_TYPE_NONE);

    return proxy->type;
}

/**
 * lm_proxy_set_type
 * @proxy: an #LmProxy
 * @type: an #LmProxyType
 *
 * Sets the proxy type for @proxy to @type.
 **/
void
lm_proxy_set_type (LmProxy *proxy, LmProxyType type)
{
    g_return_if_fail (proxy != NULL);

    proxy->type = type;
}

/**
 * lm_proxy_get_server:
 * @proxy: an #LmProxy
 *
 * Fetches the server address that @proxy is using.
 *
 * Return value: the proxy server address
 **/
const gchar *
lm_proxy_get_server (LmProxy *proxy)
{
    g_return_val_if_fail (proxy != NULL, NULL);

    return proxy->server;
}

/**
 * lm_proxy_set_server:
 * @proxy: an #LmProxy
 * @server: Address of the proxy server
 *
 * Sets the server address for @proxy to @server.
 **/
void
lm_proxy_set_server (LmProxy *proxy, const gchar *server)
{
    g_return_if_fail (proxy != NULL);
    g_return_if_fail (server != NULL);

    g_free (proxy->server);
    proxy->server = _lm_utils_hostname_to_punycode (server);
}

/**
 * lm_proxy_get_port:
 * @proxy: an #LmProxy
 *
 * Fetches the port that @proxy is using.
 *
 * Return value: The port
 **/
guint
lm_proxy_get_port (LmProxy *proxy)
{
    g_return_val_if_fail (proxy != NULL, 0);

    return proxy->port;
}

/**
 * lm_proxy_set_port:
 * @proxy: an #LmProxy
 * @port: proxy server port
 *
 * Sets the server port that @proxy will be using.
 **/
void
lm_proxy_set_port (LmProxy *proxy, guint port)
{
    g_return_if_fail (proxy != NULL);

    proxy->port = port;
}

/**
 * lm_proxy_get_username:
 * @proxy: an #LmProxy
 *
 * Fetches the username that @proxy is using.
 *
 * Return value: the username
 **/
const gchar *
lm_proxy_get_username (LmProxy *proxy)
{
    g_return_val_if_fail (proxy != NULL, NULL);

    return proxy->username;
}

/**
 * lm_proxy_set_username:
 * @proxy: an #LmProxy
 * @username: Username
 *
 * Sets the username for @proxy to @username or %NULL to unset.
 **/
void
lm_proxy_set_username (LmProxy *proxy, const gchar *username)
{
    g_return_if_fail (proxy != NULL);

    g_free (proxy->username);

    if (username) {
        proxy->username = g_strdup (username);
    } else {
        proxy->username = NULL;
    }
}
/**
 * lm_proxy_get_password:
 * @proxy: an #LmProxy
 *
 * Fetches the password that @proxy is using.
 *
 * Return value: the proxy password
 **/
const gchar *
lm_proxy_get_password (LmProxy *proxy)
{
    g_return_val_if_fail (proxy != NULL, NULL);

    return proxy->password;
}

/**
 * lm_proxy_set_password:
 * @proxy: an #LmProxy
 * @password: Password
 *
 * Sets the password for @proxy to @password or %NULL to unset.
 **/
void
lm_proxy_set_password (LmProxy *proxy, const gchar *password)
{
    g_return_if_fail (proxy != NULL);

    g_free (proxy->password);

    if (password) {
        proxy->password = g_strdup (password);
    } else {
        proxy->password = NULL;
    }
}

/**
 * lm_proxy_ref:
 * @proxy: an #LmProxy
 *
 * Adds a reference to @proxy.
 *
 * Return value: the proxy
 **/
LmProxy *
lm_proxy_ref (LmProxy *proxy)
{
    g_return_val_if_fail (proxy != NULL, NULL);

    proxy->ref_count++;
    return proxy;
}

/**
 * lm_proxy_unref
 * @proxy: an #LmProxy
 *
 * Removes a reference from @proxy. When no more references are present
 * @proxy is freed.
 **/
void
lm_proxy_unref (LmProxy *proxy)
{
    g_return_if_fail (proxy != NULL);

    proxy->ref_count--;

    if (proxy->ref_count == 0) {
        proxy_free (proxy);
    }
}
