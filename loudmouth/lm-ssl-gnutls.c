/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2003-2006 Imendio AB
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
#include <glib.h>

#include "lm-debug.h"
#include "lm-error.h"
#include "lm-ssl-base.h"
#include "lm-ssl-internals.h"

#ifdef HAVE_GNUTLS

#include <gnutls/x509.h>

#define CA_PEM_FILE "/etc/ssl/certs/ca-certificates.crt"

struct _LmSSL {
    LmSSLBase base;

    gnutls_session_t                 gnutls_session;
    gnutls_certificate_credentials_t gnutls_xcred;
    gboolean                         started;
};

static gboolean       ssl_verify_certificate    (LmSSL       *ssl,
                                                 const gchar *server);

static gboolean
ssl_verify_certificate (LmSSL *ssl, const gchar *server)
{
    LmSSLBase *base;
    unsigned int        status;
    int rc;

    base = LM_SSL_BASE (ssl);

    /* This verification function uses the trusted CAs in the credentials
     * structure. So you must have installed one or more CA certificates.
     */
    rc = gnutls_certificate_verify_peers2 (ssl->gnutls_session, &status);

    if (rc == GNUTLS_E_NO_CERTIFICATE_FOUND) {
        if (base->func (ssl,
                        LM_SSL_STATUS_NO_CERT_FOUND,
                        base->func_data) != LM_SSL_RESPONSE_CONTINUE) {
            return FALSE;
        }
    }

    if (rc != 0) {
        if (base->func (ssl,
                        LM_SSL_STATUS_GENERIC_ERROR,
                        base->func_data) != LM_SSL_RESPONSE_CONTINUE) {
            return FALSE;
        }
    }

    if (rc == GNUTLS_E_NO_CERTIFICATE_FOUND) {
        if (base->func (ssl,
                        LM_SSL_STATUS_NO_CERT_FOUND,
                        base->func_data) != LM_SSL_RESPONSE_CONTINUE) {
            return FALSE;
        }
    }

    if (status & GNUTLS_CERT_INVALID
        || status & GNUTLS_CERT_REVOKED) {
        if (base->func (ssl, LM_SSL_STATUS_UNTRUSTED_CERT,
                        base->func_data) != LM_SSL_RESPONSE_CONTINUE) {
            return FALSE;
        }
    }

    if (gnutls_certificate_expiration_time_peers (ssl->gnutls_session) < time (0)) {
        if (base->func (ssl, LM_SSL_STATUS_CERT_EXPIRED,
                        base->func_data) != LM_SSL_RESPONSE_CONTINUE) {
            return FALSE;
        }
    }

    if (gnutls_certificate_activation_time_peers (ssl->gnutls_session) > time (0)) {
        if (base->func (ssl, LM_SSL_STATUS_CERT_NOT_ACTIVATED,
                        base->func_data) != LM_SSL_RESPONSE_CONTINUE) {
            return FALSE;
        }
    }

    if (gnutls_certificate_type_get (ssl->gnutls_session) == GNUTLS_CRT_X509) {
        const gnutls_datum_t* cert_list;
        guint cert_list_size;
        size_t digest_size;
        gnutls_x509_crt_t cert;

        cert_list = gnutls_certificate_get_peers (ssl->gnutls_session, &cert_list_size);
        if (cert_list == NULL) {
            if (base->func (ssl, LM_SSL_STATUS_NO_CERT_FOUND,
                            base->func_data) != LM_SSL_RESPONSE_CONTINUE) {
                return FALSE;
            }
        }

        gnutls_x509_crt_init (&cert);

        if (gnutls_x509_crt_import (cert, &cert_list[0],
                                    GNUTLS_X509_FMT_DER) != 0) {
            if (base->func (ssl, LM_SSL_STATUS_NO_CERT_FOUND,
                            base->func_data) != LM_SSL_RESPONSE_CONTINUE) {
                return FALSE;
            }
        }

        if (!gnutls_x509_crt_check_hostname (cert, server)) {
            if (base->func (ssl, LM_SSL_STATUS_CERT_HOSTNAME_MISMATCH,
                            base->func_data) != LM_SSL_RESPONSE_CONTINUE) {
                return FALSE;
            }
        }

        gnutls_x509_crt_deinit (cert);

        digest_size = sizeof (base->fingerprint);

        if (gnutls_fingerprint (GNUTLS_DIG_MD5, &cert_list[0],
                                base->fingerprint,
                                &digest_size) >= 0) {
            if (base->expected_fingerprint &&
                memcmp (base->expected_fingerprint,
                        base->fingerprint,
                        digest_size) &&
                base->func (ssl,
                            LM_SSL_STATUS_CERT_FINGERPRINT_MISMATCH,
                            base->func_data) != LM_SSL_RESPONSE_CONTINUE) {
                return FALSE;
            }
        }
        else if (base->func (ssl, LM_SSL_STATUS_GENERIC_ERROR,
                             base->func_data) != LM_SSL_RESPONSE_CONTINUE) {
            return FALSE;
        }
    }

    return TRUE;
}

/* From lm-ssl-protected.h */

LmSSL *
_lm_ssl_new (const gchar    *expected_fingerprint,
             LmSSLFunction   ssl_function,
             gpointer        user_data,
             GDestroyNotify  notify)
{
    LmSSL *ssl;

    ssl = g_new0 (LmSSL, 1);

    _lm_ssl_base_init ((LmSSLBase *) ssl,
                       expected_fingerprint,
                       ssl_function, user_data, notify);

    return ssl;
}

void
_lm_ssl_initialize (LmSSL *ssl)
{
    gnutls_global_init ();
    gnutls_certificate_allocate_credentials (&ssl->gnutls_xcred);
    gnutls_certificate_set_x509_trust_file(ssl->gnutls_xcred,
                                           CA_PEM_FILE,
                                           GNUTLS_X509_FMT_PEM);
}

gboolean
_lm_ssl_begin (LmSSL *ssl, gint fd, const gchar *server, GError **error)
{
    int ret;
    gboolean auth_ok = TRUE;

    gnutls_init (&ssl->gnutls_session, GNUTLS_CLIENT);
    gnutls_priority_set_direct (ssl->gnutls_session,
                        "NORMAL:+CTYPE-X.509:+CTYPE-OPENPGP:+COMP-DEFLATE:+COMP-NULL",
			NULL);
    gnutls_credentials_set (ssl->gnutls_session,
                            GNUTLS_CRD_CERTIFICATE,
                            ssl->gnutls_xcred);

    gnutls_transport_set_ptr (ssl->gnutls_session,
                              (gnutls_transport_ptr_t)(glong) fd);

    ret = gnutls_handshake (ssl->gnutls_session);

    if (ret >= 0) {
        auth_ok = ssl_verify_certificate (ssl, server);
    }

    if (ret < 0 || !auth_ok) {
        char *errmsg;

        if (!auth_ok) {
            errmsg = "authentication error";
        } else {
            errmsg = "handshake failed";
        }

        g_set_error (error,
                     LM_ERROR, LM_ERROR_CONNECTION_OPEN,
                     "*** GNUTLS %s: %s",
                     errmsg, gnutls_strerror (ret));

        return FALSE;
    }

    lm_verbose ("GNUTLS negotiated compression: %s",
                gnutls_compression_get_name (gnutls_compression_get
                                             (ssl->gnutls_session)));

    ssl->started = TRUE;

    return TRUE;
}

GIOStatus
_lm_ssl_read (LmSSL *ssl, gchar *buf, gint len, gsize *bytes_read)
{
    GIOStatus status;
    gint      b_read;

    *bytes_read = 0;
    b_read = gnutls_record_recv (ssl->gnutls_session, buf, len);

    if (b_read == GNUTLS_E_AGAIN) {
        status = G_IO_STATUS_AGAIN;
    }
    else if (b_read == 0) {
        status = G_IO_STATUS_EOF;
    }
    else if (b_read < 0) {
        status = G_IO_STATUS_ERROR;
    } else {
        *bytes_read = (guint) b_read;
        status = G_IO_STATUS_NORMAL;
    }

    return status;
}

gint
_lm_ssl_send (LmSSL *ssl, const gchar *str, gint len)
{
    gint bytes_written;

    bytes_written = gnutls_record_send (ssl->gnutls_session, str, len);

    while (bytes_written < 0) {
        if (bytes_written != GNUTLS_E_INTERRUPTED &&
            bytes_written != GNUTLS_E_AGAIN) {
            return -1;
        }

        bytes_written = gnutls_record_send (ssl->gnutls_session,
                                            str, len);
    }

    return bytes_written;
}

void
_lm_ssl_close (LmSSL *ssl)
{
    if (!ssl->started)
        return;

    gnutls_deinit (ssl->gnutls_session);
    gnutls_certificate_free_credentials (ssl->gnutls_xcred);
    gnutls_global_deinit ();
}

void
_lm_ssl_free (LmSSL *ssl)
{
    _lm_ssl_base_free_fields (LM_SSL_BASE (ssl));
    g_free (ssl);
}

#endif /* HAVE_GNUTLS */
