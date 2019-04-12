/*
 * JULEA - Flexible storage framework
 * Copyright (C) 2010-2019 Michael Kuhn
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

#include <julea-config.h>

#include <glib.h>
#include <gio/gio.h>

#include <bson.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <jhelper.h>
#include <jhelper-internal.h>

#include <jbackground-operation.h>
#include <jsemantics.h>
#include <jtrace-internal.h>

/**
 * \defgroup JHelper Helper
 *
 * Helper data structures and functions.
 *
 * @{
 **/

void
j_helper_set_nodelay (GSocketConnection* connection, gboolean enable)
{
	gint const flag = (enable) ? 1 : 0;

	GSocket* socket_;
	gint fd;

	g_return_if_fail(connection != NULL);

	j_trace_enter(G_STRFUNC, NULL);

	socket_ = g_socket_connection_get_socket(connection);
	fd = g_socket_get_fd(socket_);

	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(gint));

	j_trace_leave(G_STRFUNC);
}

void
j_helper_set_cork (GSocketConnection* connection, gboolean enable)
{
	gint const flag = (enable) ? 1 : 0;

	GSocket* socket_;
	gint fd;

	g_return_if_fail(connection != NULL);

	j_trace_enter(G_STRFUNC, NULL);

	socket_ = g_socket_connection_get_socket(connection);
	fd = g_socket_get_fd(socket_);

	setsockopt(fd, IPPROTO_TCP, TCP_CORK, &flag, sizeof(gint));

	j_trace_leave(G_STRFUNC);
}

void
j_helper_get_number_string (gchar* string, guint32 length, guint32 number)
{
	gint ret;

	/* FIXME improve */
	ret = g_snprintf(string, length, "%d", number);
	g_return_if_fail((guint)ret <= length);
}

gboolean
j_helper_execute_parallel (JBackgroundOperationFunc func, gpointer* data, guint length)
{
	JBackgroundOperation** operations;
	guint data_count = 0;

	operations = g_new(JBackgroundOperation*, length);

	for (guint i = 0; i < length; i++)
	{
		operations[i] = NULL;

		if (data[i] != NULL)
		{
			data_count++;
		}
	}

	for (guint i = 0; i < length; i++)
	{
		if (data[i] == NULL)
		{
			continue;
		}

		if (data_count > 1)
		{
			operations[i] = j_background_operation_new(func, data[i]);
		}
		else
		{
			data[i] = func(data[i]);
		}
	}

	for (guint i = 0; i < length; i++)
	{
		if (operations[i] != NULL)
		{
			data[i] = j_background_operation_wait(operations[i]);
			j_background_operation_unref(operations[i]);
		}
	}

	g_free(operations);

	return TRUE;
}

guint64
j_helper_atomic_add (guint64 volatile* ptr, guint64 val)
{
	guint64 ret;

	// FIXME check C11 atomic_fetch_add
#ifdef HAVE_SYNC_FETCH_AND_ADD
	ret = __sync_fetch_and_add(ptr, val);
#else
	G_LOCK_DEFINE_STATIC(j_helper_atomic_add);

	G_LOCK(j_helper_atomic_add);
	ret = *ptr;
	*ptr += val;
	G_UNLOCK(j_helper_atomic_add);
#endif

	return ret;
}

guint32
j_helper_hash (gchar const* str)
{
	gchar c;
	guint32 hash;

	hash = 5381;

	while ((c = *str++) != '\0')
	{
		hash = ((hash << 5) + hash) + c;
	}

	return hash;
}

/**
 * @}
 **/
