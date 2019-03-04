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

#ifndef JULEA_ITEM_DEDUP_INTERNAL_H
#define JULEA_ITEM_DEDUP_INTERNAL_H

#if !defined(JULEA_ITEM_H) && !defined(JULEA_ITEM_COMPILATION)
#error "Only <julea-item.h> can be included directly."
#endif

#include <glib.h>

#include <bson.h>

#include <julea.h>

#include <item/jcollection.h>
#include <item/jitem-dedup.h>

G_BEGIN_DECLS

G_GNUC_INTERNAL JItemDedup* j_item_dedup_new (JCollection*, gchar const*, JDistribution*);
G_GNUC_INTERNAL JItemDedup* j_item_dedup_new_from_bson (JCollection*, bson_t const*);

G_GNUC_INTERNAL JCollection* j_item_dedup_get_collection (JItemDedup*);

G_GNUC_INTERNAL bson_t* j_item_dedup_serialize (JItemDedup*, JSemantics*);
G_GNUC_INTERNAL void j_item_dedup_deserialize (JItemDedup*, bson_t const*);

G_GNUC_INTERNAL bson_oid_t const* j_item_dedup_get_id (JItemDedup*);

G_GNUC_INTERNAL gboolean j_item_dedup_get_exec (JList*, JSemantics*);

G_GNUC_INTERNAL void j_item_dedup_set_modification_time (JItemDedup*, gint64);
G_GNUC_INTERNAL void j_item_dedup_set_size (JItemDedup*, guint64);

G_END_DECLS

#endif
