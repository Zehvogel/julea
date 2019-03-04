/*
 * JULEA - Flexible storage framework
 * Copyright (C) 2010-2018 Michael Kuhn
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * \file
 **/

#ifndef JULEA_ITEM_DEDUP_H
#define JULEA_ITEM_DEDUP_H

#if !defined(JULEA_ITEM_H) && !defined(JULEA_ITEM_COMPILATION)
#error "Only <julea-item.h> can be included directly."
#endif

#include <glib.h>

#include <julea.h>

G_BEGIN_DECLS

struct JItemDedup;

typedef struct JItemDedup JItemDedup;

G_END_DECLS

#include <item/jcollection.h>

G_BEGIN_DECLS

JItemDedup* j_item_dedup_ref (JItemDedup*);
void j_item_dedup_unref (JItemDedup*);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(JItemDedup, j_item_dedup_unref)

gchar const* j_item_dedup_get_name (JItemDedup*);
JCredentials* j_item_dedup_get_credentials (JItemDedup*);

JItemDedup* j_item_dedup_create (JCollection*, gchar const*, JDistribution*, JBatch*);
void j_item_dedup_delete (JItemDedup*, JBatch*);
void j_item_dedup_get (JCollection*, JItemDedup**, gchar const*, JBatch*);

void j_item_dedup_read (JItemDedup*, gpointer, guint64, guint64, guint64*, JBatch*);
void j_item_dedup_write (JItemDedup*, gconstpointer, guint64, guint64, guint64*, JBatch*);

void j_item_dedup_get_status (JItemDedup*, JBatch*);

guint64 j_item_dedup_get_size (JItemDedup*);
gint64 j_item_dedup_get_modification_time (JItemDedup*);

guint64 j_item_dedup_get_optimal_access_size (JItemDedup*);

G_END_DECLS

#endif
