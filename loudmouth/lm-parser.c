/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2003 Imendio AB
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

#include <glib.h>

#include "lm-debug.h"
#include "lm-internals.h"
#include "lm-message-node.h"
#include "lm-parser.h"

#define SHORT_END_TAG "/>"
#define XML_MAX_DEPTH 5

#define LM_PARSER(o) ((LmParser *) o)

struct LmParser {
    LmParserMessageFunction  function;
    gpointer                 user_data;
    GDestroyNotify           notify;

    LmMessageNode           *cur_root;
    LmMessageNode           *cur_node;

    GMarkupParser           *m_parser;
    GMarkupParseContext     *context;
    gchar                   *incomplete; /* incomplete utf-8 character
                                            found at the end of buffer */
};


/* Used while parsing */
static void    parser_start_node_cb (GMarkupParseContext  *context,
                                     const gchar          *node_name,
                                     const gchar         **attribute_names,
                                     const gchar         **attribute_values,
                                     gpointer              user_data,
                                     GError              **error);
static void    parser_end_node_cb   (GMarkupParseContext  *context,
                                     const gchar          *node_name,
                                     gpointer              user_data,
                                     GError              **error);
static void    parser_text_cb       (GMarkupParseContext  *context,
                                     const gchar          *text,
                                     gsize                 text_len,
                                     gpointer              user_data,
                                     GError              **error);
static void    parser_error_cb      (GMarkupParseContext  *context,
                                     GError               *error,
                                     gpointer              user_data);

static void
parser_start_node_cb (GMarkupParseContext  *context,
                      const gchar          *node_name,
                      const gchar         **attribute_names,
                      const gchar         **attribute_values,
                      gpointer              user_data,
                      GError              **error)
{
    LmParser     *parser;
    gint          i;
    const gchar  *node_name_unq;
    const gchar  *xmlns = NULL;

    parser = LM_PARSER (user_data);;


/*  parser->cur_depth++; */

    //strip namespace prefix other than "stream:" from node_name
    node_name_unq = strrchr(node_name, ':');
    if (!node_name_unq || !strncmp(node_name, "stream:", 7))
        node_name_unq = node_name;
    else
        ++node_name_unq;

    if (!parser->cur_root) {
        /* New toplevel element */
        parser->cur_root = _lm_message_node_new (node_name_unq);
        parser->cur_node = parser->cur_root;
    } else {
        LmMessageNode *parent_node;

        parent_node = parser->cur_node;

        parser->cur_node = _lm_message_node_new (node_name_unq);
        _lm_message_node_add_child_node (parent_node,
                                         parser->cur_node);
    }

    for (i = 0; attribute_names[i]; ++i) {
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_PARSER,
               "ATTRIBUTE: %s = %s\n",
               attribute_names[i],
               attribute_values[i]);
        //FIXME: strip namespace suffix from xmlns: attribute if exists

        lm_message_node_set_attributes (parser->cur_node,
                                        attribute_names[i],
                                        attribute_values[i],
                                        NULL);
        if (!strncmp(attribute_names[i], "xmlns:", 6))
            xmlns = attribute_values[i];
    }
    if (xmlns && !lm_message_node_get_attribute(parser->cur_node, "xmlns")) {
        lm_message_node_set_attribute (parser->cur_node, "xmlns", xmlns);
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_PARSER,
               "ATTRIBUTE: %s = %s\n",
               "xmlns", xmlns);
    }

    if (strcmp ("stream:stream", node_name) == 0) {
        parser_end_node_cb (context,
                            "stream:stream",
                            user_data,
                            error);
    }
}

static void
parser_end_node_cb (GMarkupParseContext  *context,
                    const gchar          *node_name,
                    gpointer              user_data,
                    GError              **error)
{
    LmParser     *parser;
    const gchar  *node_name_unq;

    parser = LM_PARSER (user_data);

    node_name_unq = strrchr(node_name, ':');
    if (!node_name_unq || !strncmp(node_name, "stream:", 7))
        node_name_unq = node_name;
    else
        ++node_name_unq;

    g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_PARSER,
           "Trying to close node: %s\n", node_name_unq);

    if (!parser->cur_node) {
        /* FIXME: LM-1 should look at this */
        return;
    }

    //cur_node->name doesn't have namespace prefix anymore, node_name does.
    if (strcmp (parser->cur_node->name, node_name_unq) != 0) {
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_PARSER,
               "Trying to close node that isn't open: %s",
               node_name_unq);
        return;
    }

    if (parser->cur_node == parser->cur_root) {
        LmMessage *m;

        m = _lm_message_new_from_node (parser->cur_root);

        if (!m) {
            g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_PARSER,
                   "Couldn't create message: %s\n",
                   parser->cur_root->name);
        } else {
            g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_PARSER,
               "Have a new message\n");
            if (parser->function) {
                (* parser->function) (parser, m, parser->user_data);
            }
            lm_message_unref (m);
        }

        lm_message_node_unref (parser->cur_root);
        parser->cur_node = parser->cur_root = NULL;
    } else {
        LmMessageNode *tmp_node;
        tmp_node = parser->cur_node;
        parser->cur_node = parser->cur_node->parent;

        lm_message_node_unref (tmp_node);
    }
}

static void
parser_text_cb (GMarkupParseContext   *context,
                const gchar           *text,
                gsize                  text_len,
                gpointer               user_data,
                GError               **error)
{
    LmParser *parser;

    g_return_if_fail (user_data != NULL);

    parser = LM_PARSER (user_data);

    if (parser->cur_node && strcmp (text, "") != 0) {
        lm_message_node_set_value (parser->cur_node, text);
    }
}

static void
parser_error_cb (GMarkupParseContext *context,
                 GError              *error,
                 gpointer             user_data)
{
    g_return_if_fail (user_data != NULL);
    g_return_if_fail (error != NULL);

    g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_VERBOSE,
           "Parsing failed: %s\n", error->message);
}

LmParser *
lm_parser_new (LmParserMessageFunction function,
               gpointer                user_data,
               GDestroyNotify          notify)
{
    LmParser *parser;

    parser = g_new0 (LmParser, 1);
    if (!parser) {
        return NULL;
    }

    parser->m_parser = g_new0 (GMarkupParser, 1);
    if (!parser->m_parser) {
        g_free (parser);
        return NULL;
    }

    parser->function  = function;
    parser->user_data = user_data;
    parser->notify    = notify;

    parser->m_parser->start_element = parser_start_node_cb;
    parser->m_parser->end_element   = parser_end_node_cb;
    parser->m_parser->text          = parser_text_cb;
    parser->m_parser->error         = parser_error_cb;

    parser->context = g_markup_parse_context_new (parser->m_parser, 0,
                                                  parser, NULL);

    parser->cur_root = NULL;
    parser->cur_node = NULL;

    parser->incomplete = NULL;

    return parser;
}

static gchar *
_lm_parser_make_valid (const gchar *buffer, gchar **incomplete)
{
    GString *string;
    const gchar *remainder, *invalid;
    gint remaining_bytes, valid_bytes;
    gunichar code; /*error code for invalid character*/

    g_return_val_if_fail (buffer != NULL, NULL);

    string = NULL;
    remainder = buffer;
    remaining_bytes = strlen (buffer);

    while (remaining_bytes != 0)
    {
        if (g_utf8_validate (remainder, remaining_bytes, &invalid))
            break;
        valid_bytes = invalid - remainder;

        if (string == NULL)
            string = g_string_sized_new (remaining_bytes);

        g_string_append_len (string, remainder, valid_bytes);

        remainder = g_utf8_find_next_char(invalid, NULL);
        remaining_bytes -= valid_bytes + (remainder - invalid);

        code = g_utf8_get_char_validated (invalid, -1);

        if (code == -1) {
            /* A complete but invalid codepoint */
            /* append U+FFFD REPLACEMENT CHARACTER */
            g_string_append (string, "\357\277\275");
            g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_VERBOSE, "invalid character!\n");
        } else if (code == -2) {
            /* Beginning of what could be a character */
            *incomplete = g_strdup (invalid);
            g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_VERBOSE,
                           "incomplete character: %s\n", *incomplete);

            g_assert (remaining_bytes == 0);
            g_assert (*(g_utf8_find_next_char(invalid, NULL)) == '\0');
        }
    }

    if (string == NULL)
        return g_strdup (buffer);

    g_string_append (string, remainder);

    g_assert (g_utf8_validate (string->str, -1, NULL));

    return g_string_free (string, FALSE);
}


gboolean
lm_parser_parse (LmParser *parser, const gchar *string)
{
    gboolean parsed;
    gchar *valid, *completed;
    g_return_val_if_fail (parser != NULL, FALSE);

    if (!parser->context) {
        parser->context = g_markup_parse_context_new (parser->m_parser, 0,
                                                      parser, NULL);
    }
    if (parser->incomplete) {
        completed = g_strdup_printf("%s%s", parser->incomplete, string);
        g_free(parser->incomplete);
        parser->incomplete = NULL;
    } else {
        completed = g_strdup(string);
    }
    valid = _lm_parser_make_valid (completed, &parser->incomplete);
    g_free(completed);
    if (g_markup_parse_context_parse (parser->context, valid,
                                      (gssize)strlen (valid), NULL)) {
        parsed = TRUE;
    } else {
        g_markup_parse_context_free (parser->context);
        parser->context = NULL;
        parsed = FALSE;
    }
    g_free(valid);
    return parsed;
}

void
lm_parser_free (LmParser *parser)
{
    if (parser->notify) {
        (* parser->notify) (parser->user_data);
    }

    if (parser->context) {
        g_markup_parse_context_free (parser->context);
    }
    g_free (parser->incomplete);
    g_free (parser->m_parser);
    g_free (parser);
}

