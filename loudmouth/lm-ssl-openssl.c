/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2006 Imendio AB
 * Copyright (C) 2006 Nokia Corporation. All rights reserved.
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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>

#include "lm-debug.h"
#include "lm-error.h"
#include "lm-ssl-base.h"
#include "lm-ssl-internals.h"

#ifdef HAVE_OPENSSL

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/safestack.h>

#define LM_SSL_CN_MAX       63

struct _LmSSL {
    LmSSLBase base;

    const SSL_METHOD *ssl_method;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    /*BIO *bio;*/
};

int ssl_verify_cb (int preverify_ok, X509_STORE_CTX *x509_ctx);

static gboolean ssl_verify_certificate (LmSSL *ssl, const gchar *server);
static GIOStatus ssl_io_status_from_return (LmSSL *ssl, gint error);

/*static char _ssl_error_code[11];*/

static void
ssl_print_state (LmSSL *ssl, const char *func, int val)
{
    unsigned long errid;
    const char *errmsg;

    switch (SSL_get_error(ssl->ssl, val)) {
    case SSL_ERROR_NONE:
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL, "%s(): %i / SSL_ERROR_NONE",
                   func, val);
        break;
    case SSL_ERROR_ZERO_RETURN:
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL,
                   "%s(): %i / SSL_ERROR_ZERO_RETURN", func, val);
        break;
    case SSL_ERROR_WANT_READ:
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL,
                   "%s(): %i / SSL_ERROR_WANT_READ", func, val);
        break;
    case SSL_ERROR_WANT_WRITE:
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL,
                   "%s(): %i / SSL_ERROR_WANT_WRITE", func, val);
        break;
    case SSL_ERROR_WANT_X509_LOOKUP:
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL,
                   "%s(): %i / SSL_ERROR_WANT_X509_LOOKUP", func, val);
        break;
    case SSL_ERROR_SYSCALL:
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL,
                   "%s(): %i / SSL_ERROR_SYSCALL", func, val);
        break;
    case SSL_ERROR_SSL:
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL,
                   "%s(): %i / SSL_ERROR_SSL", func, val);
        break;
    }
    do {
        errid = ERR_get_error();
        if (errid) {
            errmsg = ERR_error_string(errid, NULL);
            g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL, "\t%s", errmsg);
        }
    } while (errid != 0);
}

/*static const char *
  ssl_get_x509_err (long verify_res)
  {
  sprintf(_ssl_error_code, "%ld", verify_res);
  return _ssl_error_code;
  }*/


int
ssl_verify_cb (int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    /* As this callback doesn't get auxiliary pointer parameter we
     * cannot really use this. However, we can retrieve results later. */
    return 1;
}

static gboolean
ssl_match_domain_name (const gchar *server, const gchar *domain)
{
    if (domain[0]=='*' && domain[1]=='.') {
        /* leftmost part wildcard */
        ++domain;

        if (strchr(domain, '*') != NULL) {
            /* multiple wildcards not allowed */
            return FALSE;
        }

        server = strchr(server, '.'); /* eat the leftmost part */
        if (server == NULL) {
            return FALSE;
        }

        /* fall thru for wildcard match */
    }

    return (!strcasecmp(server, domain));
}

/* side effect: fills the ssl->fingerprint buffer */
static gboolean
ssl_verify_certificate (LmSSL *ssl, const gchar *server)
{
    gboolean retval = TRUE;
    gboolean match_result = FALSE;
    LmSSLBase *base;
    long verify_res;
    int rc;
    const EVP_MD *digest = EVP_sha256();
    unsigned int digest_len;
    guchar digest_bin[EVP_MD_size(digest)];
    X509 *srv_crt;
    gchar *cn;
    X509_NAME *crt_subj;

    base = LM_SSL_BASE(ssl);

    g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL,
           "%s: Cipher: %s/%s/%i\n",
           __FILE__,
           SSL_get_cipher_version(ssl->ssl),
           SSL_get_cipher_name(ssl->ssl),
           SSL_get_cipher_bits(ssl->ssl, NULL));

    verify_res = SSL_get_verify_result(ssl->ssl);
    srv_crt = SSL_get_peer_certificate(ssl->ssl);
    rc = X509_digest(srv_crt, digest, digest_bin, &digest_len);
    if ((rc != 0) && (digest_len == EVP_MD_size(digest))) {
        _lm_ssl_base_set_fingerprint(base, digest_bin, digest_len);
        if (_lm_ssl_base_check_fingerprint(base) != 0) {
            if (base->func(ssl,
                           LM_SSL_STATUS_CERT_FINGERPRINT_MISMATCH,
                           base->func_data) != LM_SSL_RESPONSE_CONTINUE) {
                return FALSE;
            }
        }
    } else {
      if (base->func(ssl,
                     LM_SSL_STATUS_GENERIC_ERROR,
                     base->func_data) != LM_SSL_RESPONSE_CONTINUE) {
          return FALSE;
      }
    }
    g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL,
           "%s: SSL_get_verify_result() = %ld\n",
           __FILE__,
           verify_res);
    switch (verify_res) {
    case X509_V_OK:
        break;
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    case X509_V_ERR_UNABLE_TO_GET_CRL:
        if (base->func(ssl,
                       LM_SSL_STATUS_NO_CERT_FOUND,
                       base->func_data) != LM_SSL_RESPONSE_CONTINUE) {
            retval = FALSE;
        }
        break;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        /* special case for self signed certificates? */
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    case X509_V_ERR_INVALID_CA:
    case X509_V_ERR_CERT_UNTRUSTED:
    case X509_V_ERR_CERT_REVOKED:
        if (base->func(ssl,
                       LM_SSL_STATUS_UNTRUSTED_CERT,
                       base->func_data) != LM_SSL_RESPONSE_CONTINUE) {
            retval = FALSE;
        }
        break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_CRL_NOT_YET_VALID:
        if (base->func(ssl,
                       LM_SSL_STATUS_CERT_NOT_ACTIVATED,
                       base->func_data) != LM_SSL_RESPONSE_CONTINUE) {
            retval = FALSE;
        }
        break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_CRL_HAS_EXPIRED:
        if (base->func(ssl,
                       LM_SSL_STATUS_CERT_EXPIRED,
                       base->func_data) != LM_SSL_RESPONSE_CONTINUE) {
            retval = FALSE;
        }
        break;
    default:
        if (base->func(ssl, LM_SSL_STATUS_GENERIC_ERROR,
                       base->func_data) != LM_SSL_RESPONSE_CONTINUE) {
            retval = FALSE;
        }
    }
    /*if (retval == FALSE) {
      g_set_error (error, LM_ERROR, LM_ERROR_CONNECTION_OPEN,
      ssl_get_x509_err(verify_res), NULL);
      }*/
    crt_subj = X509_get_subject_name(srv_crt);
    cn = (gchar *) g_malloc0(LM_SSL_CN_MAX + 1);

    /* FWB: deprecated call, can only get first entry */
    if (X509_NAME_get_text_by_NID(crt_subj, NID_commonName, cn, LM_SSL_CN_MAX) > 0) {

        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL,
               "%s: server = '%s', cn = '%s'\n",
               __FILE__, server, cn);

        if (cn != NULL && ssl_match_domain_name(server, cn)) {
            match_result = TRUE;
        } else {
            /* g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL, "%s: CN does not match server name\n", __FILE__); */
        }
    } else {
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL,
               "X509_NAME_get_text_by_NID() failed");
    }

    /* RFC6125: "...However, it is perfectly acceptable for the subject field to be empty,
     * as long as the certificate contains a subject alternative name ("subjectAltName")
     * extension that includes at least one subjectAltName entry"
     */
    if (!match_result) {
        /* FWB: CN doesn't match, try SANs */
        int subject_alt_names_nb = -1;
        int san_counter;
        STACK_OF(GENERAL_NAME) *subject_alt_names = NULL;

        // Try to extract the names within the SAN extension from the certificate
        subject_alt_names = X509_get_ext_d2i((X509 *) srv_crt, NID_subject_alt_name, NULL, NULL);
        if (subject_alt_names != NULL) {

            // Check each name within the extension
            subject_alt_names_nb = sk_GENERAL_NAME_num(subject_alt_names);
            for (san_counter=0; san_counter<subject_alt_names_nb; san_counter++) {
                const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(subject_alt_names, san_counter);
                if (current_name->type == GEN_DNS) {
                    // Current name is a DNS name, let's check it, it's ASCII
                    if (ssl_match_domain_name(server, (const char *)current_name->d.dNSName->data)) {
                        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL, "%s: found SAN '%s' - MATCH\n", __FILE__, current_name->d.dNSName->data);
                        match_result = TRUE; /* break; */
                    } else {
                        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL, "%s: found SAN '%s'\n", __FILE__, current_name->d.dNSName->data);
                    }
                }
            }

        }

        sk_GENERAL_NAME_pop_free(subject_alt_names, GENERAL_NAME_free);
    }

    if (!match_result) {
        if (base->func (ssl,
                        LM_SSL_STATUS_CERT_HOSTNAME_MISMATCH,
                        base->func_data) != LM_SSL_RESPONSE_CONTINUE) {
            retval = FALSE;
        }
    }

    g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL,
           "%s:\n\tIssuer: %s\n\tSubject: %s\n\tFor: %s\n",
           __FILE__,
           X509_NAME_oneline(X509_get_issuer_name(srv_crt), NULL, 0),
           X509_NAME_oneline(X509_get_subject_name(srv_crt), NULL, 0),
           cn);

    g_free(cn);

    return retval;
}

static GIOStatus
ssl_io_status_from_return (LmSSL *ssl, gint ret)
{
    gint      error;
    GIOStatus status;

    if (ret > 0) return G_IO_STATUS_NORMAL;

    error = SSL_get_error(ssl->ssl, ret);
    switch (error) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        status = G_IO_STATUS_AGAIN;
        break;
    case SSL_ERROR_ZERO_RETURN:
        status = G_IO_STATUS_EOF;
        break;
    default:
        status = G_IO_STATUS_ERROR;
    }

    return status;
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
    static gboolean initialized = FALSE;
    /*const char *cert_file = NULL;*/

    if (!initialized) {
        SSL_library_init();
        /* FIXME: Is this needed when we are not in debug? */
        SSL_load_error_strings();
        initialized = TRUE;
    }

    /* don't use TLSv1_client_method() because otherwise we don't get
     * connections to TLS1_1 and TLS1_2 only servers
     */
    ssl->ssl_method = SSLv23_client_method();
    if (ssl->ssl_method == NULL) {
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL,
               "SSLv23_client_method() == NULL");
        abort();
    }
    ssl->ssl_ctx = SSL_CTX_new(ssl->ssl_method);
    if (ssl->ssl_ctx == NULL) {
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL, "SSL_CTX_new() == NULL");
        abort();
    }

    /* Set the NO_TICKET option on the context to allow for talk to Google Talk
     * which apparently seems to be having a problem handling empty session
     * tickets due to a bug in Java.
     *
     * See http://twistedmatrix.com/trac/ticket/3463 and
     * Loudmouth [#28].
     */
    SSL_CTX_set_options (ssl->ssl_ctx, (SSL_OP_NO_TICKET | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3));

    /*if (access("/etc/ssl/cert.pem", R_OK) == 0)
      cert_file = "/etc/ssl/cert.pem";
      if (!SSL_CTX_load_verify_locations(ssl->ssl_ctx,
      cert_file, "/etc/ssl/certs")) {
      g_warning("SSL_CTX_load_verify_locations() failed");
      }*/
    SSL_CTX_set_verify (ssl->ssl_ctx, SSL_VERIFY_PEER, ssl_verify_cb);
}

gboolean
_lm_ssl_set_ca (LmSSL       *ssl,
                const gchar *ca_path)
{
    struct stat target;
    int success = 0;

    if (stat (ca_path, &target) != 0) {
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL,
               "ca_path '%s': no such file or directory", ca_path);
        return FALSE;
    }

    if (S_ISDIR (target.st_mode)) {
        success = SSL_CTX_load_verify_locations(ssl->ssl_ctx, NULL, ca_path);
    } else if (S_ISREG (target.st_mode)) {
        success = SSL_CTX_load_verify_locations(ssl->ssl_ctx, ca_path, NULL);
    }
    if (success == 0) {
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL,
               "Loading of ca_path '%s' failed: %s",
               ca_path,
               ERR_error_string(ERR_peek_last_error(), NULL));
        return FALSE;
    }

    return TRUE;
}

gboolean
_lm_ssl_begin (LmSSL *ssl, gint fd, const gchar *server, GError **error)
{
    gint ssl_ret;
    GIOStatus status;
    LmSSLBase *base;

    base = LM_SSL_BASE(ssl);
    if (!ssl->ssl_ctx) {
        g_set_error (error,
                     LM_ERROR, LM_ERROR_CONNECTION_OPEN,
                     "No SSL Context for OpenSSL");
        return FALSE;
    }

    if (base->cipher_list) {
        SSL_CTX_set_cipher_list(ssl->ssl_ctx, base->cipher_list);
    }
    if (base->ca_path) {
        _lm_ssl_set_ca (ssl, base->ca_path);
    } else {
        SSL_CTX_set_default_verify_paths (ssl->ssl_ctx);
    }

    ssl->ssl = SSL_new(ssl->ssl_ctx);
    if (ssl->ssl == NULL) {
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL, "SSL_new() == NULL");
        g_set_error(error, LM_ERROR, LM_ERROR_CONNECTION_OPEN,
                    "SSL_new()");
        return FALSE;
    }

    if (!SSL_set_fd (ssl->ssl, fd)) {
        g_log (LM_LOG_DOMAIN, LM_LOG_LEVEL_SSL, "SSL_set_fd() failed");
        g_set_error(error, LM_ERROR, LM_ERROR_CONNECTION_OPEN,
                    "SSL_set_fd()");
        return FALSE;
    }
    /*ssl->bio = BIO_new_socket (fd, BIO_NOCLOSE);
      if (ssl->bio == NULL) {
      g_warning("BIO_new_socket() failed");
      g_set_error(error, LM_ERROR, LM_ERROR_CONNECTION_OPEN,
      "BIO_new_socket()");
      return FALSE;
      }
      SSL_set_bio(ssl->ssl, ssl->bio, ssl->bio);*/

    do {
        ssl_ret = SSL_connect(ssl->ssl);
        if (ssl_ret <= 0) {
            status = ssl_io_status_from_return(ssl, ssl_ret);
            if (status != G_IO_STATUS_AGAIN) {
                ssl_print_state(ssl, "SSL_connect",
                                ssl_ret);
                g_set_error(error, LM_ERROR,
                            LM_ERROR_CONNECTION_OPEN,
                            "SSL_connect()");
                return FALSE;
            }

        }
    } while (ssl_ret <= 0);

    if (!ssl_verify_certificate (ssl, server)) {
        g_set_error (error, LM_ERROR, LM_ERROR_CONNECTION_OPEN,
                     "*** SSL certificate verification failed");
        return FALSE;
    }

    return TRUE;
}

GIOStatus
_lm_ssl_read (LmSSL *ssl, gchar *buf, gint len, gsize *bytes_read)
{
    GIOStatus status;
    gint ssl_ret;

    *bytes_read = 0;
    ssl_ret = SSL_read(ssl->ssl, buf, len);
    status = ssl_io_status_from_return(ssl, ssl_ret);
    if (status == G_IO_STATUS_NORMAL) {
        *bytes_read = ssl_ret;
    }

    return status;
}

gint
_lm_ssl_send (LmSSL *ssl, const gchar *str, gint len)
{
    GIOStatus status;
    gint ssl_ret;

    do {
        ssl_ret = SSL_write(ssl->ssl, str, len);
        if (ssl_ret <= 0) {
            status = ssl_io_status_from_return(ssl, ssl_ret);
            if (status != G_IO_STATUS_AGAIN)
                return -1;
        }
    } while (ssl_ret <= 0);

    return ssl_ret;
}

void
_lm_ssl_close (LmSSL *ssl)
{
    if (ssl->ssl != NULL) {
        SSL_shutdown(ssl->ssl);
        SSL_free(ssl->ssl);
        ssl->ssl = NULL;
    }
}

void
_lm_ssl_free (LmSSL *ssl)
{
    SSL_CTX_free(ssl->ssl_ctx);
    ssl->ssl_ctx = NULL;

    _lm_ssl_base_free_fields (LM_SSL_BASE(ssl));
    g_free (ssl);
}

#endif /* HAVE_GNUTLS */
