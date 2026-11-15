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

/**
 * SECTION:lm-utils
 * @Title: Miscellaneous Utility Functions
 * @Short_description: Miscellaneous Utility Functions
 *
 * Functions to help application developers when writing XMPP applications using Loudmouth.
 */

#include <config.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <glib.h>

#ifndef G_OS_WIN32
#include <unistd.h>
#endif

#ifdef HAVE_IDN
#include <stringprep.h>
#include <punycode.h>
#include <idna.h>
#endif

#include "lm-internals.h"
#include "lm-utils.h"

LmCallback *
_lm_utils_new_callback (gpointer       func,
                        gpointer       user_data,
                        GDestroyNotify notify)
{
    LmCallback *cb;

    cb = g_new0 (LmCallback, 1);
    cb->func = func;
    cb->user_data = user_data;
    cb->notify = notify;

    return cb;
}

void
_lm_utils_free_callback (LmCallback *cb)
{
    if (!cb) {
        return;
    }

    if (cb->notify) {
        (* cb->notify) (cb->user_data);
    }
    g_free (cb);
}

gchar *
_lm_utils_generate_id (void)
{
    static guint  last_id = 0;
    gint64        now;
    glong         val, usec;

    now = g_get_real_time ();
    usec = now % G_USEC_PER_SEC;
    val = ((now / G_USEC_PER_SEC) & usec) + last_id++;

    return g_strdup_printf ("%ld%ld", val, usec);
}

gchar*
_lm_utils_hostname_to_punycode (const gchar *hostname)
{
#ifdef HAVE_IDN
    char *s;
    uint32_t *q;
    int rc;
    gchar *result;

    q = stringprep_utf8_to_ucs4 (hostname, -1, NULL);
    if (q == NULL) {
        return g_strdup (hostname);
    }

    rc = idna_to_ascii_4z (q, &s, IDNA_ALLOW_UNASSIGNED);
    free(q);
    if (rc != IDNA_SUCCESS) {
        return g_strdup (hostname);
    }

    /* insures result is allocated through glib */
    result = g_strdup(s);
    free(s);

    return result;
#else
    return g_strdup(hostname);
#endif
}

/**
 * lm_utils_get_localtime:
 * @stamp: An XMPP timestamp
 *
 * Converts an XMPP timestamp to a struct tm showing local time.
 *
 * Return value: The local time struct.
 **/
struct tm *
lm_utils_get_localtime (const gchar *stamp)
{
    struct tm tm;
    time_t    t;
    gint      year, month;

    g_return_val_if_fail (stamp != NULL, NULL);

    /* 20021209T23:51:30 */

    sscanf (stamp, "%4d%2d%2dT%2d:%2d:%2d",
            &year, &month, &tm.tm_mday, &tm.tm_hour,
            &tm.tm_min, &tm.tm_sec);

    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_isdst = -1;

    t = mktime (&tm);

#if defined(HAVE_TM_GMTOFF)
    t += tm.tm_gmtoff;
#elif defined(HAVE_TIMEZONE)
    t -= timezone;
    if (tm.tm_isdst > 0) {
        t += 3600;
    }
#endif

    return localtime (&t);
}


