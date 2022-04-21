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

#ifndef __LM_ASYNCNS_RESOLVER_H__
#define __LM_ASYNCNS_RESOLVER_H__

#include <config.h>

#include <glib-object.h>

#ifdef HAVE_ASYNCNS
#define freeaddrinfo(x) asyncns_freeaddrinfo(x)
#endif

#include "lm-resolver.h"

G_BEGIN_DECLS

#define LM_TYPE_ASYNCNS_RESOLVER            (lm_asyncns_resolver_get_type ())
#define LM_ASYNCNS_RESOLVER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), LM_TYPE_ASYNCNS_RESOLVER, LmAsyncnsResolver))
#define LM_ASYNCNS_RESOLVER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), LM_TYPE_ASYNCNS_RESOLVER, LmAsyncnsResolverClass))
#define LM_IS_ASYNCNS_RESOLVER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), LM_TYPE_ASYNCNS_RESOLVER))
#define LM_IS_ASYNCNS_RESOLVER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LM_TYPE_ASYNCNS_RESOLVER))
#define LM_ASYNCNS_RESOLVER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), LM_TYPE_ASYNCNS_RESOLVER, LmAsyncnsResolverClass))

typedef struct LmAsyncnsResolver      LmAsyncnsResolver;
typedef struct LmAsyncnsResolverClass LmAsyncnsResolverClass;

struct LmAsyncnsResolver {
    LmResolver parent;
};

struct LmAsyncnsResolverClass {
    LmResolverClass parent_class;
};

GType   lm_asyncns_resolver_get_type  (void);

G_END_DECLS

#endif /* __LM_ASYNCNS_RESOLVER_H__ */

