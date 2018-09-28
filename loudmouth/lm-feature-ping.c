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

#include "lm-connection.h"
#include "lm-debug.h"
#include "lm-internals.h"
#include "lm-marshal.h"
#include "lm-misc.h"

#include "lm-feature-ping.h"

#define XMPP_NS_PING "urn:xmpp:ping"

#define GET_PRIV(obj) (lm_feature_ping_get_instance_private (LM_FEATURE_PING(obj)))

typedef struct LmFeaturePingPrivate LmFeaturePingPrivate;
struct LmFeaturePingPrivate {
    LmConnection *connection;
    guint         keep_alive_rate;
    GSource      *keep_alive_source;
    guint         keep_alive_counter;
};

static void     feature_ping_finalize            (GObject           *object);
static void     feature_ping_get_property        (GObject           *object,
                                                  guint              param_id,
                                                  GValue            *value,
                                                  GParamSpec        *pspec);
static void     feature_ping_set_property        (GObject           *object,
                                                  guint              param_id,
                                                  const GValue      *value,
                                                  GParamSpec        *pspec);

static LmHandlerResult
feature_ping_keep_alive_reply                    (LmMessageHandler *handler,
                                                  LmConnection     *connection,
                                                  LmMessage        *m,
                                                  gpointer          user_data);
static gboolean feature_ping_send_keep_alive     (LmFeaturePing    *fp);

G_DEFINE_TYPE_WITH_PRIVATE (LmFeaturePing, lm_feature_ping, G_TYPE_OBJECT)

enum {
    PROP_0,
    PROP_CONNECTION,
    PROP_RATE
};

enum {
    TIMED_OUT,
    LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void
lm_feature_ping_class_init (LmFeaturePingClass *class)
{
    GObjectClass *object_class = G_OBJECT_CLASS (class);

    object_class->finalize     = feature_ping_finalize;
    object_class->get_property = feature_ping_get_property;
    object_class->set_property = feature_ping_set_property;

    g_object_class_install_property (object_class,
                                     PROP_CONNECTION,
                                     g_param_spec_pointer ("connection",
                                                           "Connection",
                                                           "The LmConnection to use",
                                                           G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));

    g_object_class_install_property (object_class,
                                     PROP_RATE,
                                     g_param_spec_uint ("rate",
                                                        "Timeout Rate",
                                                        "Keep alive rate in seconds",
                                                        0, G_MAXUINT,
                                                        0,
                                                        G_PARAM_READWRITE));

    signals[TIMED_OUT] =
        g_signal_new ("timed-out",
                      G_OBJECT_CLASS_TYPE (object_class),
                      G_SIGNAL_RUN_LAST,
                      0,
                      NULL, NULL,
                      _lm_marshal_VOID__VOID,
                      G_TYPE_NONE, 0);
}

static void
lm_feature_ping_init (LmFeaturePing *feature_ping)
{
    (void) GET_PRIV (feature_ping);
}

static void
feature_ping_finalize (GObject *object)
{
    (void) GET_PRIV (object);

    (G_OBJECT_CLASS (lm_feature_ping_parent_class)->finalize) (object);
}

static void
feature_ping_get_property (GObject    *object,
                           guint       param_id,
                           GValue     *value,
                           GParamSpec *pspec)
{
    LmFeaturePingPrivate *priv;

    priv = GET_PRIV (object);

    switch (param_id) {
    case PROP_RATE:
        g_value_set_uint (value, priv->keep_alive_rate);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, param_id, pspec);
        break;
    };
}

static void
feature_ping_set_property (GObject      *object,
                           guint         param_id,
                           const GValue *value,
                           GParamSpec   *pspec)
{
    LmFeaturePingPrivate *priv;

    priv = GET_PRIV (object);

    switch (param_id) {
    case PROP_CONNECTION:
        priv->connection = g_value_get_pointer (value);
        break;
    case PROP_RATE:
        priv->keep_alive_rate = g_value_get_uint (value);
        /* Restart the pings */
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, param_id, pspec);
        break;
    };
}

static LmHandlerResult
feature_ping_keep_alive_reply (LmMessageHandler *handler,
                               LmConnection     *connection,
                               LmMessage        *m,
                               gpointer          user_data)
{
    LmFeaturePingPrivate *priv;

    priv = GET_PRIV (user_data);

    priv->keep_alive_counter = 0;

    return LM_HANDLER_RESULT_REMOVE_MESSAGE;
}

static gboolean
feature_ping_send_keep_alive (LmFeaturePing *fp)
{
    LmFeaturePingPrivate *priv;
    LmMessage         *ping;
    LmMessageNode     *ping_node;
    LmMessageHandler  *keep_alive_handler;
    gchar             *server;

    priv = GET_PRIV (fp);

    priv->keep_alive_counter++;
    if (priv->keep_alive_counter > 3) {
        g_signal_emit (fp, signals[TIMED_OUT], 0);
       return FALSE;
        /* FIXME */
#if 0 /* Should be moved to signal callback in LmConnection */
        connection_do_close (connection);
        connection_signal_disconnect (connection,
                                      LM_DISCONNECT_REASON_PING_TIME_OUT);
#endif

    }

    server = _lm_connection_get_server (priv->connection);

    ping = lm_message_new_with_sub_type (server,
                                         LM_MESSAGE_TYPE_IQ,
                                         LM_MESSAGE_SUB_TYPE_GET);

    ping_node = lm_message_node_add_child (ping->node, "ping", NULL);

    lm_message_node_set_attribute (ping_node, "xmlns", XMPP_NS_PING);

    keep_alive_handler =
        lm_message_handler_new (feature_ping_keep_alive_reply,
                                fp,
                                FALSE);

    if (!lm_connection_send_with_reply (priv->connection,
                                        ping,
                                        keep_alive_handler,
                                        NULL)) {
        lm_verbose ("Error while sending XMPP ping!\n");
    }

    lm_message_handler_unref (keep_alive_handler);
    lm_message_unref (ping);
    g_free (server);

    return TRUE;
}


void
lm_feature_ping_start (LmFeaturePing *fp)
{
    LmFeaturePingPrivate *priv;

    g_return_if_fail (LM_IS_FEATURE_PING (fp));

    priv = GET_PRIV (fp);

    if (priv->keep_alive_source) {
        lm_feature_ping_stop (fp);
    }

    if (priv->keep_alive_rate > 0) {
        priv->keep_alive_counter = 0;
        priv->keep_alive_source =
            lm_misc_add_timeout (_lm_connection_get_context (priv->connection),
                                 priv->keep_alive_rate * 1000,
                                 (GSourceFunc) feature_ping_send_keep_alive,
                                 fp);
    }
}

void
lm_feature_ping_stop (LmFeaturePing *fp)
{
    LmFeaturePingPrivate *priv;

    g_return_if_fail (LM_IS_FEATURE_PING (fp));

    priv = GET_PRIV (fp);

    if (priv->keep_alive_source) {
        g_source_destroy (priv->keep_alive_source);
    }

    priv->keep_alive_source = NULL;
}


