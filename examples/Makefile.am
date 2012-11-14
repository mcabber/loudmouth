include $(top_srcdir)/build/Makefile.am.lm

AM_CPPFLAGS =                                       \
    -I$(top_srcdir)                                 \
    $(LOUDMOUTH_CFLAGS)

noinst_PROGRAMS =                                   \
    test-lm                                         \
    test-http-proxy                                 \
    test-tunnel                                     \
    lm-send-async                                   \
    lm-change-password                              \
    lm-register

test_lm_SOURCES = test-lm.c

test_http_proxy_SOURCES = test-http-proxy.c

test_tunnel_SOURCES = test-tunnel.c

lm_send_async_SOURCES = lm-send-async.c

lm_change_password_SOURCES = lm-change-password.c

lm_register_SOURCES = lm-register.c

LDADD =                                             \
    $(LOUDMOUTH_LIBS)                               \
    $(top_builddir)/loudmouth/libloudmouth-1.la
