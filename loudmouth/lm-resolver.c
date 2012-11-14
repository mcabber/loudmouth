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
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <config.h>

#include <string.h>

/* Needed on Mac OS X */
#if HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif

#include <arpa/nameser.h>
#include <resolv.h>

#include "lm-asyncns-resolver.h"
#include "lm-blocking-resolver.h"
#include "lm-debug.h"
#include "lm-internals.h"
#include "lm-marshal.h"
#include "lm-resolver.h"

#define GET_PRIV(obj) (G_TYPE_INSTANCE_GET_PRIVATE ((obj), LM_TYPE_RESOLVER, LmResolverPriv))

typedef struct LmResolverPriv LmResolverPriv;
struct LmResolverPriv {
    GMainContext       *context;

    LmResolverCallback  callback;
    gpointer            user_data;

    /* -- Properties -- */
    LmResolverType      type;
    gchar              *host;
    guint               port;

    /* For SRV lookups */
    gchar              *domain;
    gchar              *service;
    gchar              *protocol;

    /* The results */
    LmResolverResult    result;
    struct addrinfo    *results;
    struct addrinfo    *current_result;
};

static void     resolver_finalize            (GObject           *object);
static void     resolver_get_property        (GObject           *object,
                                              guint              param_id,
                                              GValue            *value,
                                              GParamSpec        *pspec);
static void     resolver_set_property        (GObject           *object,
                                              guint              param_id,
                                              const GValue      *value,
                                              GParamSpec        *pspec);

G_DEFINE_TYPE (LmResolver, lm_resolver, G_TYPE_OBJECT)

enum {
    PROP_0,
    PROP_CONTEXT,
    PROP_TYPE,
    PROP_HOST,
    PROP_PORT,
    PROP_DOMAIN,
    PROP_SERVICE,
    PROP_PROTOCOL
};

static void
lm_resolver_class_init (LmResolverClass *class)
{
    GObjectClass *object_class = G_OBJECT_CLASS (class);

    object_class->finalize     = resolver_finalize;
    object_class->get_property = resolver_get_property;
    object_class->set_property = resolver_set_property;

    g_object_class_install_property (object_class,
                                     PROP_CONTEXT,
                                     g_param_spec_pointer ("context",
                                                           "Context",
                                                           "Main context to use",
                                                           G_PARAM_READWRITE));

    g_object_class_install_property (object_class,
                                     PROP_TYPE,
                                     g_param_spec_int ("type",
                                                       "Type",
                                                       "Resolver Type",
                                                       LM_RESOLVER_HOST,
                                                       LM_RESOLVER_SRV,
                                                       LM_RESOLVER_HOST,
                                                       G_PARAM_READWRITE));

    g_object_class_install_property (object_class,
                                     PROP_HOST,
                                     g_param_spec_string ("host",
                                                          "Host",
                                                          "Host to lookup",
                                                          NULL,
                                                          G_PARAM_READWRITE));

    g_object_class_install_property (object_class,
                                     PROP_PORT,
                                     g_param_spec_uint ("port",
                                                        "Port",
                                                        "Port number",
                                                        0,
                                                        LM_MAX_PORT,
                                                        0,
                                                        G_PARAM_READWRITE));

    g_object_class_install_property (object_class,
                                     PROP_DOMAIN,
                                     g_param_spec_string ("domain",
                                                          "Domain",
                                                          "Domain to lookup",
                                                          NULL,
                                                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

    g_object_class_install_property (object_class,
                                     PROP_SERVICE,
                                     g_param_spec_string ("service",
                                                          "Service",
                                                          "Service to lookup",
                                                          NULL,
                                                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

    g_object_class_install_property (object_class,
                                     PROP_PROTOCOL,
                                     g_param_spec_string ("protocol",
                                                          "Protocol",
                                                          "Protocol for SRV lookup",
                                                          NULL,
                                                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

    g_type_class_add_private (object_class, sizeof (LmResolverPriv));
}

static void
lm_resolver_init (LmResolver *resolver)
{
    (void) GET_PRIV (resolver);
}

static void
resolver_finalize (GObject *object)
{
    LmResolverPriv *priv;

    priv = GET_PRIV (object);

    g_free (priv->host);
    g_free (priv->domain);
    g_free (priv->service);
    g_free (priv->protocol);

    if (priv->context) {
        g_main_context_unref (priv->context);
    }

    if (priv->results) {
        freeaddrinfo (priv->results);
    }

    (G_OBJECT_CLASS (lm_resolver_parent_class)->finalize) (object);
}

static void
resolver_get_property (GObject    *object,
                       guint       param_id,
                       GValue     *value,
                       GParamSpec *pspec)
{
    LmResolverPriv *priv;

    priv = GET_PRIV (object);

    switch (param_id) {
    case PROP_CONTEXT:
        g_value_set_pointer (value, priv->context);
        break;
    case PROP_TYPE:
        g_value_set_int (value, priv->type);
        break;
    case PROP_HOST:
        g_value_set_string (value, priv->host);
        break;
    case PROP_PORT:
        g_value_set_uint (value, priv->port);
        break;
    case PROP_DOMAIN:
        g_value_set_string (value, priv->domain);
        break;
    case PROP_SERVICE:
        g_value_set_string (value, priv->service);
        break;
    case PROP_PROTOCOL:
        g_value_set_string (value, priv->protocol);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, param_id, pspec);
        break;
    };
}

static void
resolver_set_property (GObject      *object,
                       guint         param_id,
                       const GValue *value,
                       GParamSpec   *pspec)
{
    LmResolverPriv *priv;

    priv = GET_PRIV (object);

    switch (param_id) {
    case PROP_CONTEXT:
        if (priv->context) {
            g_main_context_unref (priv->context);
        }

        priv->context = (GMainContext *) g_value_get_pointer (value);
        g_main_context_ref (priv->context);
        break;
    case PROP_TYPE:
        priv->type = g_value_get_int (value);
        break;
    case PROP_HOST:
        g_free (priv->host);
        priv->host = g_value_dup_string (value);
        break;
    case PROP_PORT:
        priv->port = g_value_get_uint (value);
        break;
    case PROP_DOMAIN:
        g_free (priv->domain);
        priv->domain = g_value_dup_string (value);
        break;
    case PROP_SERVICE:
        g_free (priv->service);
        priv->service = g_value_dup_string (value);
        break;
    case PROP_PROTOCOL:
        g_free (priv->protocol);
        priv->protocol = g_value_dup_string (value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, param_id, pspec);
        break;
    };
}

LmResolver *
lm_resolver_new (GMainContext *context)
{
    LmResolver *resolver;

#ifdef HAVE_ASYNCNS
    resolver = g_object_new (LM_TYPE_ASYNCNS_RESOLVER, NULL);
#else
    resolver = g_object_new (LM_TYPE_BLOCKING_RESOLVER, NULL);
#endif

    g_object_set (resolver, "context", context, NULL);

    return resolver;
}

static GType
resolver_get_gtype (void)
{
#ifdef HAVE_ASYNCNS
    return LM_TYPE_ASYNCNS_RESOLVER;
#else
    return LM_TYPE_BLOCKING_RESOLVER;
#endif /* HAVE_ASYNCNS */
}

LmResolver *
lm_resolver_new_for_host (const gchar        *host,
                          LmResolverCallback  callback,
                          gpointer            user_data)
{
    LmResolver     *resolver;
    LmResolverPriv *priv;

    g_return_val_if_fail (host != NULL, NULL);
    g_return_val_if_fail (callback != NULL, NULL);

    resolver =  g_object_new (resolver_get_gtype (),
                              "type", LM_RESOLVER_HOST,
                              "host", host,
                              NULL);

    priv = GET_PRIV (resolver);

    priv->callback = callback;
    priv->user_data = user_data;

    return resolver;
}

LmResolver *
lm_resolver_new_for_service (const gchar        *domain,
                             const gchar        *service,
                             const gchar        *protocol,
                             LmResolverCallback  callback,
                             gpointer            user_data)
{
    LmResolver     *resolver;
    LmResolverPriv *priv;

    g_return_val_if_fail (domain != NULL, NULL);
    g_return_val_if_fail (service != NULL, NULL);
    g_return_val_if_fail (protocol != NULL, NULL);
    g_return_val_if_fail (callback != NULL, NULL);

    resolver = g_object_new (resolver_get_gtype (),
                             "type", LM_RESOLVER_SRV,
                             "domain", domain,
                             "service", service,
                             "protocol", protocol,
                             NULL);

    priv = GET_PRIV (resolver);

    priv->callback = callback;
    priv->user_data = user_data;

    return resolver;
}

void
lm_resolver_lookup (LmResolver *resolver)
{
    if (!LM_RESOLVER_GET_CLASS(resolver)) {
        g_assert_not_reached ();
    }

    LM_RESOLVER_GET_CLASS(resolver)->lookup (resolver);
}

void
lm_resolver_cancel (LmResolver *resolver)
{
    if (!LM_RESOLVER_GET_CLASS(resolver)->cancel) {
        g_assert_not_reached ();
    }

    LM_RESOLVER_GET_CLASS(resolver)->cancel (resolver);
}

/* To iterate through the results */
struct addrinfo *
lm_resolver_results_get_next (LmResolver *resolver)
{
    LmResolverPriv  *priv;
    struct addrinfo *ret_val;

    g_return_val_if_fail (LM_IS_RESOLVER (resolver), NULL);

    priv = GET_PRIV (resolver);

skipresult:
    if (!priv->current_result) {
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_VERBOSE,
               "no more results from resolver\n");
        return NULL;
    };

    ret_val = priv->current_result;
    priv->current_result = priv->current_result->ai_next;
    if (ret_val->ai_family != AF_INET) {
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_VERBOSE,
               "skipping non-IPv4 resolver entry\n");
        goto skipresult;
    };

    return ret_val;
}

void
lm_resolver_results_reset (LmResolver *resolver)
{
    LmResolverPriv *priv;

    g_return_if_fail (LM_IS_RESOLVER (resolver));

    priv = GET_PRIV (resolver);

    priv->current_result = priv->results;
}

gchar *
_lm_resolver_create_srv_string (const gchar *domain,
                                const gchar *service,
                                const gchar *protocol)
{
    g_return_val_if_fail (domain != NULL, NULL);
    g_return_val_if_fail (service != NULL, NULL);
    g_return_val_if_fail (protocol != NULL, NULL);

    return g_strdup_printf ("_%s._%s.%s", service, protocol, domain);
}

void
_lm_resolver_set_result (LmResolver       *resolver,
                         LmResolverResult  result,
                         struct addrinfo  *results)
{
    LmResolverPriv *priv;

    g_return_if_fail (LM_IS_RESOLVER (resolver));

    priv = GET_PRIV (resolver);

    priv->result = result;
    priv->results = priv->current_result = results;

    lm_verbose ("Calling resolver callback: %s\n", priv->host);

    priv->callback (resolver, result, priv->user_data);
}

gboolean
_lm_resolver_parse_srv_response (unsigned char  *srv,
                                 int             srv_len,
                                 gchar         **out_server,
                                 guint          *out_port)
{
    int                  qdcount;
    int                  ancount;
    int                  len;
    const unsigned char *pos;
    unsigned char       *end;
    HEADER              *head;
    char                 name[256];
    char                 pref_name[256];
    guint                pref_port = 0;
    guint                pref_prio = 9999;

    pref_name[0] = 0;

    pos = srv + sizeof (HEADER);
    end = srv + srv_len;
    head = (HEADER *) srv;

    qdcount = ntohs (head->qdcount);
    ancount = ntohs (head->ancount);

    /* Ignore the questions */
    while (qdcount-- > 0 && (len = dn_expand (srv, end, pos, name, 255)) >= 0) {
        g_assert (len >= 0);
        pos += len + QFIXEDSZ;
    }

    /* Parse the answers */
    while (ancount-- > 0 && (len = dn_expand (srv, end, pos, name, 255)) >= 0) {
        /* Ignore the initial string */
        uint16_t pref, port;

        g_assert (len >= 0);
        pos += len;
        /* Ignore type, ttl, class and dlen */
        pos += 10;
        GETSHORT (pref, pos);
        GETSHORT (port, pos);

        len = dn_expand (srv, end, pos, name, 255);
        if (pref < pref_prio) {
            pref_prio = pref;
            strcpy (pref_name, name);
            pref_port = port;
        }
        pos += len;
    }

    if (pref_name[0]) {
        *out_server = g_strdup (pref_name);
        *out_port = pref_port;
        return TRUE;
    }
    return FALSE;
}

