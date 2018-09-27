/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2008 Imendio AB
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

#include <string.h>
#include <sys/types.h>
#include <netdb.h>

/* Needed on Mac OS X */
#if HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "lm-marshal.h"
#include "lm-misc.h"

#include "lm-blocking-resolver.h"

#define SRV_LEN 8192

#define GET_PRIV(obj) (lm_blocking_resolver_get_instance_private (LM_BLOCKING_RESOLVER(obj)))

typedef struct LmBlockingResolverPrivate LmBlockingResolverPrivate;
struct LmBlockingResolverPrivate {
    GSource *idle_source;
};

static void     blocking_resolver_dispose     (GObject       *object);
static void     blocking_resolver_lookup      (LmResolver    *resolver);
static void     blocking_resolver_cancel      (LmResolver    *resolver);

G_DEFINE_TYPE_WITH_PRIVATE (LmBlockingResolver, lm_blocking_resolver, LM_TYPE_RESOLVER)

static void
lm_blocking_resolver_class_init (LmBlockingResolverClass *class)
{
    GObjectClass    *object_class   = G_OBJECT_CLASS (class);
    LmResolverClass *resolver_class = LM_RESOLVER_CLASS (class);

    object_class->dispose = blocking_resolver_dispose;

    resolver_class->lookup = blocking_resolver_lookup;
    resolver_class->cancel = blocking_resolver_cancel;
}

static void
lm_blocking_resolver_init (LmBlockingResolver *blocking_resolver)
{
}

static void
blocking_resolver_dispose (GObject *object)
{
    /* Ensure we don't have an idle around */
    blocking_resolver_cancel (LM_RESOLVER (object));

    (G_OBJECT_CLASS (lm_blocking_resolver_parent_class)->dispose) (object);
}

static gboolean
blocking_resolver_lookup_host (LmBlockingResolver *resolver)
{
    gchar           *host;
    struct addrinfo  req;
    struct addrinfo *ans;
    int              err;
    gboolean         retval = TRUE;

    g_object_get (resolver, "host", &host, NULL);

    /* Lookup */

    memset (&req, 0, sizeof(req));
    req.ai_family   = PF_UNSPEC;
    req.ai_socktype = SOCK_STREAM;
    req.ai_protocol = IPPROTO_TCP;

    err = getaddrinfo (host, NULL, &req, &ans);

    if (err != 0) {
        _lm_resolver_set_result (LM_RESOLVER (resolver), LM_RESOLVER_RESULT_FAILED,
                                 NULL);

        retval = FALSE;
    }

    if (ans == NULL) {
        /* Couldn't find any results */
        g_object_ref (resolver);
        _lm_resolver_set_result (LM_RESOLVER (resolver), LM_RESOLVER_RESULT_FAILED,
                                 NULL);

        g_object_unref (resolver);
        retval = FALSE;
    }

    /* FIXME: How to set and iterate the results */
    /*priv->results    = ans;
      priv->cur_result = ans; */

    if (retval) {
        g_object_ref (resolver);

        _lm_resolver_set_result (LM_RESOLVER (resolver), LM_RESOLVER_RESULT_OK,
                                 ans);

        g_object_unref (resolver);
    }

    g_free (host);

    return retval;
}

static gboolean
blocking_resolver_lookup_service (LmBlockingResolver *resolver)
{
    gchar *domain;
    gchar *service;
    gchar *protocol;
    gchar *srv;
    gchar *new_server = NULL;
    guint  new_port = 0;
    gboolean  result;
    unsigned char    srv_ans[SRV_LEN];
    int              len;
    gboolean         retval = TRUE;

    g_object_get (resolver,
                  "domain", &domain,
                  "service", &service,
                  "protocol", &protocol,
                  NULL);

    srv = _lm_resolver_create_srv_string (domain, service, protocol);

    res_init ();

    len = res_query (srv, C_IN, T_SRV, srv_ans, SRV_LEN);

    result = _lm_resolver_parse_srv_response (srv_ans, len,
                                              &new_server, &new_port);
    if (result == FALSE) {
        retval = FALSE;
    }

    g_object_set (resolver,
                  "host", new_server,
                  "port", new_port,
                  NULL);

    g_object_ref (resolver);
    _lm_resolver_set_result (LM_RESOLVER (resolver), LM_RESOLVER_RESULT_OK, NULL);
    g_object_unref (resolver);

    /* Lookup the new server and the new port */
   /* blocking_resolver_lookup_host (resolver); */

    g_free (new_server);
    g_free (srv);
    g_free (domain);
    g_free (service);
    g_free (protocol);

    return retval;
}

static gboolean
blocking_resolver_idle_lookup (LmBlockingResolver *resolver)
{
    LmBlockingResolverPrivate *priv = GET_PRIV (resolver);
    gint                    type;

    /* Start the DNS querying */

    /* Decide if we are going to lookup a srv or host */
    g_object_get (resolver, "type", &type, NULL);

    switch (type) {
    case LM_RESOLVER_HOST:
        blocking_resolver_lookup_host (resolver);
        break;
    case LM_RESOLVER_SRV:
        blocking_resolver_lookup_service (resolver);
        break;
    };

    /* End of DNS querying */
    priv->idle_source = NULL;
    return FALSE;
}

static void
blocking_resolver_lookup (LmResolver *resolver)
{
    LmBlockingResolverPrivate *priv;
    GMainContext           *context;

    g_return_if_fail (LM_IS_BLOCKING_RESOLVER (resolver));

    priv = GET_PRIV (resolver);

    g_object_get (resolver, "context", &context, NULL);

    priv->idle_source = lm_misc_add_idle (context,
                                          (GSourceFunc) blocking_resolver_idle_lookup,
                                          resolver);
}

static void
blocking_resolver_cancel (LmResolver *resolver)
{
    LmBlockingResolverPrivate *priv;

    g_return_if_fail (LM_IS_BLOCKING_RESOLVER (resolver));

    priv = GET_PRIV (resolver);

    if (priv->idle_source) {
        g_source_destroy (priv->idle_source);
        priv->idle_source = NULL;
    }
}
