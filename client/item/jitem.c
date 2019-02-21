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

#include <julea-config.h>

#include <glib.h>

#include <string.h>

#include <bson.h>

#include <item/jitem.h>
#include <item/jitem-internal.h>

#include <item/jcollection.h>
#include <item/jcollection-internal.h>

#include <julea.h>
#include <julea-internal.h>
#include <julea-kv.h>
#include <julea-object.h>

#include <openssl/evp.h>

/**
 * \defgroup JItem Item
 *
 * Data structures and functions for managing items.
 *
 * @{
 **/

struct JItemGetData
{
	JCollection* collection;
	JItem** item;
};

typedef struct JItemGetData JItemGetData;

/**
 * A JItem.
 **/
struct JItem
{
	/**
	 * The ID.
	 **/
	bson_oid_t id;

	/**
	 * The name.
	 **/
	gchar* name;

	JCredentials* credentials;
	JDistribution* distribution;

	JKV* kv;
	JKV* kv_h;
	JDistributedObject* object;

	/**
	 * The status.
	 **/
	struct
	{
		guint64 age;

		/**
		 * The size.
		 * Stored in bytes.
		 */
		guint64 size;

		/**
		 * The time of the last modification.
		 * Stored in microseconds since the Epoch.
		 */
		gint64 modification_time;
	}
	status;

	/**
	 * The parent collection.
	 **/
	JCollection* collection;

	/**
	 * The reference count.
	 **/
	gint ref_count;

	/**
	 * The hashes the item consists of
	 */
	GArray* hashes;

	/**
	 * Chunk size for static hashing
	 */
	guint64 chunk_size;
};

/**
 * Increases an item's reference count.
 *
 * \author Michael Kuhn
 *
 * \code
 * JItem* i;
 *
 * j_item_ref(i);
 * \endcode
 *
 * \param item An item.
 *
 * \return #item.
 **/
JItem*
j_item_ref (JItem* item)
{
	g_return_val_if_fail(item != NULL, NULL);

	j_trace_enter(G_STRFUNC, NULL);

	g_atomic_int_inc(&(item->ref_count));

	j_trace_leave(G_STRFUNC);

	return item;
}

/**
 * Decreases an item's reference count.
 * When the reference count reaches zero, frees the memory allocated for the item.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param item An item.
 **/
void
j_item_unref (JItem* item)
{
	g_return_if_fail(item != NULL);

	j_trace_enter(G_STRFUNC, NULL);

	if (g_atomic_int_dec_and_test(&(item->ref_count)))
	{
		if (item->kv != NULL)
		{
			j_kv_unref(item->kv);
		}

		if (item->kv_h != NULL)
		{
			j_kv_unref(item->kv_h);
		}

		if (item->object != NULL)
		{
			j_distributed_object_unref(item->object);
		}

		if (item->collection != NULL)
		{
			j_collection_unref(item->collection);
		}

		j_credentials_unref(item->credentials);
		j_distribution_unref(item->distribution);

		g_free(item->name);

		g_slice_free(JItem, item);
	}

	j_trace_leave(G_STRFUNC);
}

/**
 * Returns an item's name.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param item An item.
 *
 * \return The name.
 **/
gchar const*
j_item_get_name (JItem* item)
{
	g_return_val_if_fail(item != NULL, NULL);

	j_trace_enter(G_STRFUNC, NULL);
	j_trace_leave(G_STRFUNC);

	return item->name;
}

/**
 * Creates an item in a collection.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param collection   A collection.
 * \param name         A name.
 * \param distribution A distribution.
 * \param batch        A batch.
 *
 * \return A new item. Should be freed with j_item_unref().
 **/
JItem*
j_item_create (JCollection* collection, gchar const* name, JDistribution* distribution, JBatch* batch)
{
	JItem* item;
	bson_t* value;

	g_return_val_if_fail(collection != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	j_trace_enter(G_STRFUNC, NULL);

	if ((item = j_item_new(collection, name, distribution)) == NULL)
	{
		goto end;
	}

	value = j_item_serialize(item, j_batch_get_semantics(batch));

	j_distributed_object_create(item->object, batch);
	j_kv_put(item->kv, value, batch);

end:
	j_trace_leave(G_STRFUNC);

	return item;
}

static
void
j_item_get_callback (bson_t const* value, gpointer data_)
{
	JItemGetData* data = data_;

	*(data->item) = j_item_new_from_bson(data->collection, value);

	j_collection_unref(data->collection);
	g_slice_free(JItemGetData, data);
}

/**
 * Gets an item from a collection.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param collection A collection.
 * \param item       A pointer to an item.
 * \param name       A name.
 * \param batch      A batch.
 **/
void
j_item_get (JCollection* collection, JItem** item, gchar const* name, JBatch* batch)
{
	JItemGetData* data;
	g_autoptr(JKV) kv = NULL;
	g_autofree gchar* path = NULL;

	g_return_if_fail(collection != NULL);
	g_return_if_fail(item != NULL);
	g_return_if_fail(name != NULL);

	j_trace_enter(G_STRFUNC, NULL);

	data = g_slice_new(JItemGetData);
	data->collection = j_collection_ref(collection);
	data->item = item;

	path = g_build_path("/", j_collection_get_name(collection), name, NULL);
	kv = j_kv_new("items", path);
	j_kv_get_callback(kv, j_item_get_callback, data, batch);

	j_trace_leave(G_STRFUNC);
}

/**
 * Deletes an item from a collection.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param collection A collection.
 * \param item       An item.
 * \param batch      A batch.
 **/
void
j_item_delete (JItem* item, JBatch* batch)
{
	g_return_if_fail(item != NULL);
	g_return_if_fail(batch != NULL);

	j_trace_enter(G_STRFUNC, NULL);

	j_kv_delete(item->kv, batch);
	j_kv_delete(item->kv_h, batch);
	j_distributed_object_delete(item->object, batch);

	j_trace_leave(G_STRFUNC);
}

/**
 * Reads an item.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param item       An item.
 * \param data       A buffer to hold the read data.
 * \param length     Number of bytes to read.
 * \param offset     An offset within #item.
 * \param bytes_read Number of bytes read.
 * \param batch      A batch.
 **/
void
j_item_read (JItem* item, gpointer data, guint64 length, guint64 offset, guint64* bytes_read, JBatch* batch)
{
	g_return_if_fail(item != NULL);
	g_return_if_fail(data != NULL);
	g_return_if_fail(bytes_read != NULL);

	j_trace_enter(G_STRFUNC, NULL);
	guint64 chunks, first_chunk;

	bson_t b;
	bson_init (&b);
	j_kv_get(item->kv_h, &b, batch);

	// statt zeug hier im read zu machen die sachen beim get holen bzw beim
	// new from bson

	j_batch_execute(batch);
	printf("Read Hashes Len %d\n",  item->hashes->len);

	gchar* json = bson_as_json (&b, NULL);
	//gchar* json = bson_as_canonical_extended_json(b, NULL);
	g_print("JSON read %s\n", json);
	bson_free(json);
	//j_item_deserialize_hashes(hashes, b);

	first_chunk = offset / item->chunk_size;
	chunks = length / item->chunk_size;
	

	JDistributedObject *chunk_obj;
	for(guint64 chunk = first_chunk; chunk < chunks; chunk++)
	{
		const gchar* hash = g_array_index(item->hashes, guchar*, chunk);
		printf("Read Hash: %s\n", hash);
		chunk_obj = j_distributed_object_new("chunks", hash, item->distribution);
		j_distributed_object_create(chunk_obj, batch);
		j_distributed_object_read(chunk_obj, (const gchar*)data + chunk * item->chunk_size - first_chunk*item->chunk_size, item->chunk_size, 0, bytes_read, batch);
	}
	//j_distributed_object_read(item->object, data, length, offset, bytes_read, batch);

	j_trace_leave(G_STRFUNC);
}


// bson_t*
// j_item_serialize_hashes (JItemHashes* hashes)
// {
// 	bson_t* b;
// 
// 	g_return_val_if_fail(hashes != NULL, NULL);
// 
// 	j_trace_enter(G_STRFUNC, NULL);
// 
// 	b = bson_new();
// 
// 	g_print("md_len: %lu\n", hashes->hash_len);
// 	g_print("num_hashes: %lu\n", hashes->hash_cnt);
// 
// 	BSON_APPEND_INT64(b, "md_len", hashes->hash_len);
// 	BSON_APPEND_INT64(b, "num_hashes", hashes->hash_cnt);
// 
// 	bson_t b_document;
// 
// //	bson_append_document_begin(b, "hashes", -1, &b_document);
// 
// 	//for (int i = 0; i < hashes->hash_cnt; i++)
// 	//	bson_append_utf8(&b_document, g_strdup_printf("%d", i), -1, (const gchar*)(hashes->hashes + i * hashes->hash_len), hashes->hash_len);
// 
// 	//bson_append_document_end(b, &b_document);
// 
// 	//bson_destroy(b_document);
// 
// 
// 	//bson_finish(b);
// 
// 
// 	j_trace_leave(G_STRFUNC);
// 
// 	return b;
// }
// 
// void
// j_item_deserialize_hashes (JItemHashes* hashes, bson_t const* b)
// {
// 	bson_iter_t iterator;
// 	bson_iter_t hash_iterator;
// 
// 	g_return_if_fail(hashes != NULL);
// 	g_return_if_fail(b != NULL);
// 
// 	j_trace_enter(G_STRFUNC, NULL);
// 
// 	bson_iter_init(&iterator, b);
// 
// 	while (bson_iter_next(&iterator))
// 	{
// 		gchar const* key;
// 
// 		key = bson_iter_key(&iterator);
// 
// 		if (g_strcmp0(key, "md_len") == 0 && BSON_ITER_HOLDS_INT64(&iterator))
// 		{
// 			hashes->hash_len = bson_iter_int64(&iterator);
// 		}
// 		else if (g_strcmp0(key, "num_hashes") == 0 && BSON_ITER_HOLDS_INT64(&iterator))
// 		{
// 			hashes->hash_cnt = bson_iter_int64(&iterator);
// 		}
// 		else if (g_strcmp0(key, "hashes") == 0 && BSON_ITER_HOLDS_DOCUMENT(&iterator))
// 		{
// 			const guint8* data;
// 			guint32 length;
// 
// 			bson_iter_document(&iterator, &length, &data);
// 			bson_iter_init_from_data(&hash_iterator, data, length);
// 
// 		}
// 	}
// 	hashes->hashes = g_slice_alloc(hashes->hash_cnt * hashes->hash_len);
// 	guint64 i = 0;
// 	while (bson_iter_next(&hash_iterator))
// 	{
// 		if (BSON_ITER_HOLDS_UTF8(&hash_iterator))
// 		{
// 			printf("i: %lu\n", i);
// 			//FIXME: use g_strdup
// 			g_stpcpy((gchar*) &hashes->hashes[i*hashes->hash_len], bson_iter_utf8(&hash_iterator, NULL /*FIXME*/));
// 			i++;
// 		}
// 	}
// 
// 	j_trace_leave(G_STRFUNC);
// }

static
void
j_item_hash_ref_callback (bson_t const* value, gpointer data_)
{
	bson_iter_t iter;
	guint32* refcount = data_;

	if (bson_iter_init_find(&iter, value, "ref"))
		*refcount = (guint32)bson_iter_int32(&iter);
}
/**
 * Writes an item.
 *
 * \note
 * j_item_write() modifies bytes_written even if j_batch_execute() is not called.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param item          An item.
 * \param data          A buffer holding the data to write.
 * \param length        Number of bytes to write.
 * \param offset        An offset within #item.
 * \param bytes_written Number of bytes written.
 * \param batch         A batch.
 **/
void
j_item_write (JItem* item, gconstpointer data, guint64 length, guint64 offset, guint64* bytes_written, JBatch* batch)
{
	g_return_if_fail(item != NULL);
	g_return_if_fail(data != NULL);
	g_return_if_fail(bytes_written != NULL);

	j_trace_enter(G_STRFUNC, NULL);

	guint64 first_chunk, chunk_offset, chunks, old_chunks, hash_len, last_chunk, remaining, bytes_read;
	GArray* hashes;
	gpointer first_buf, last_buf; // was wohl der type von last_buf ist :thinking:
	JDistributedObject *first_obj, *last_obj, *chunk_obj;
	JKV *chunk_kv;
	bson_t *new_ref_bson;
 	guchar hash_gen[EVP_MAX_MD_SIZE];
 	guint md_len;
	JBatch* sub_batch = j_batch_new(j_batch_get_semantics(batch));
 	EVP_MD_CTX *mdctx = EVP_MD_CTX_create();

	// needs to be modified for non static hashing
	first_chunk = offset / item->chunk_size;
	chunk_offset = offset % item->chunk_size;
	chunks = length / item->chunk_size;
	//last_chunk = first_chunk + chunks - 1; // might be unecesarry
	remaining = chunks * item->chunk_size - chunk_offset - length;
	printf("Chunk Size: %ld\n", item->chunk_size);
	printf("First_chunk: %ld\n", first_chunk);
	printf("Offset: %ld\n", offset);
	printf("Chunk Offset: %ld\n", chunk_offset);
	printf("Chunks: %ld\n", chunks);
	printf("remaining: %ld\n", remaining);
	printf("Length: %ld\n", length);

	hash_len = g_array_get_element_size(item->hashes);

	old_chunks = MIN(0, MIN(chunks, item->hashes->len - first_chunk));
	hashes = g_array_sized_new(FALSE, TRUE, hash_len, old_chunks);
	g_array_insert_vals(hashes, 0, item->hashes->data, old_chunks * hash_len);

	//g_array_set_size(item->hashes, chunks);
	// get old_chunks:
	// first_chunk if chunk_offset nonzero
	// last_chunk if remaining is nonzero
	if (chunk_offset > 0 && old_chunks > 0)
	{
		// get offset part of first_chunk
		first_buf = g_slice_alloc(chunk_offset);
		first_obj = j_distributed_object_new("chunks", g_array_index(hashes, gchar*, 0), item->distribution);
		j_distributed_object_create(first_obj, sub_batch);
		j_distributed_object_read(first_obj, first_buf, chunk_offset, item->chunk_size - chunk_offset, &bytes_read, sub_batch);
	}
	else if (chunk_offset > 0)
	{
		first_buf = g_slice_alloc0(chunk_offset);
	}

	if (remaining > 0 && old_chunks == chunks)
	{
		// get remaining part of last_chunk
		last_buf = g_slice_alloc(remaining);
		last_obj = j_distributed_object_new("chunks", g_array_index(hashes, gchar*, chunks - 1), item->distribution);
		j_distributed_object_create(last_obj, sub_batch);
		j_distributed_object_read(last_obj, last_buf, item->chunk_size - remaining, remaining, &bytes_read, sub_batch);
	}
	else if (remaining > 0)
	{
		last_buf = g_slice_alloc0(remaining);
	}

	j_batch_execute(sub_batch);
	for (guint64 chunk = 0; chunk < chunks; chunk++)
	{
		guint32 refcount = 0;
		EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
		if (chunk == 0)
		{
			EVP_DigestUpdate(mdctx, first_buf, chunk_offset);
			EVP_DigestUpdate(mdctx, data, item->chunk_size - chunk_offset);
		}
		else if (chunk == chunks - 1)
		{
			EVP_DigestUpdate(mdctx, (const gchar*)data + chunk * item->chunk_size, item->chunk_size - chunk_offset);
			EVP_DigestUpdate(mdctx, last_buf, remaining);
		}
		else
		{
			EVP_DigestUpdate(mdctx, (const gchar*)data + chunk * item->chunk_size, item->chunk_size);
		}
		EVP_DigestFinal_ex(mdctx, hash_gen, &md_len);

		// Generate the usable hash
		GString *hash_string = g_string_new (NULL);
		for(unsigned int i = 0; i < md_len; i++){
			g_string_append_printf(hash_string, "%02x", hash_gen[i]);
		}		
		gchar* hash = hash_string->str;
		printf("Write Hash: %s\n", hash);

		chunk_kv = j_kv_new("chunk_refs", (const gchar*)hash);
		//ref_bson = bson_new();
		// puh, hier vielleicht doch mit callback arbeiten weil ich ja
		// keine ahnung hab wann ich den bson da aufräumen kann :/
		// das könnte man sich alles sparen wenn objekte globalen
		// refcount hätten...
		//j_kv_get(chunk_kv, ref_bson, batch); // yay batching
		j_kv_get_callback(chunk_kv, j_item_hash_ref_callback, &refcount, sub_batch);
		j_batch_execute(sub_batch);
		

		if (refcount == 0)
		{
			guint64 chunk_bytes_written = 0;
			chunk_obj = j_distributed_object_new("chunks", (const gchar*)hash, item->distribution);
			j_distributed_object_create(chunk_obj, batch);

			if (chunk == 0)
			{
				if(chunk_offset > 0) // Im "Idealfall" ist chunk_offset = 0, aber geht nicht wegen g_return_if_fail()
					j_distributed_object_write(chunk_obj, first_buf, chunk_offset, 0, &chunk_bytes_written, batch);
				j_distributed_object_write(chunk_obj, data, item->chunk_size - chunk_offset, chunk_offset, &chunk_bytes_written, batch);

			}
			else if (chunk == chunks -1)
			{
				j_distributed_object_write(chunk_obj, (const gchar*)data + chunk * item->chunk_size, item->chunk_size - remaining, 0, &chunk_bytes_written, batch);
				if(remaining > 0) // Gleicher Fall wie oben
					j_distributed_object_write(chunk_obj, last_buf, remaining, item->chunk_size - remaining, &chunk_bytes_written, batch);
			}
			else
			{
				j_distributed_object_write(chunk_obj, (const gchar*)data + chunk * item->chunk_size, item->chunk_size, 0, &chunk_bytes_written, batch);
			}
			//*bytes_written += chunk_bytes_written;
		}
		
		new_ref_bson = bson_new();
		bson_append_int32(new_ref_bson, "ref", -1, refcount+1);
		j_kv_put(chunk_kv, new_ref_bson, sub_batch);
		j_batch_execute(sub_batch);
		// öh was passiert überhaupt bei put wenn es da schon was gibt?
		// 	in LevelDB überschreibt neuer value den alten
		// 	in LMDB per default wohl auch
		// 	MongoDB backend benutzt eh replace statt insert

		if (chunk < old_chunks)
		{
			gchar* old_hash = g_array_index(item->hashes, gchar*, chunk);
			if (g_strcmp0(old_hash, (gchar*)hash) != 0)
			{
				chunk_kv = j_kv_new("chunk_refs", (const gchar*)old_hash);
				j_kv_get_callback(chunk_kv, j_item_hash_ref_callback, &refcount, sub_batch);
				j_batch_execute(sub_batch);
				refcount -= 1;
				if (refcount > 0)
				{
					new_ref_bson = bson_new();
					bson_append_int32(new_ref_bson, "ref", -1, refcount);
					j_kv_put(chunk_kv, new_ref_bson, batch);
				}
				else
				{
					j_kv_delete(chunk_kv, batch);
					chunk_obj = j_distributed_object_new("chunks", (const gchar*)old_hash, item->distribution);
					j_distributed_object_delete(chunk_obj, batch);
					j_distributed_object_unref(chunk_obj);
				}
				g_array_remove_index(item->hashes, chunk);
				//TODO: free old_hash
				//g_array_insert_val(item->hashes, chunk, hash); // Nach unten verschoben, da immer ausführen?
			}
		}	

		g_array_insert_val(item->hashes, chunk, hash);

		//printf("hash'%s'\n", g_array_index(item->hashes, guchar*, chunk));
		// kann man einen bson_t nicht einfach modifizieren? :(
	}
	EVP_MD_CTX_destroy(mdctx);
	// for each chunk:
	// 	calculate hash
	// 	o_new(hash)
	// 	okv_check_and_ref(hash)
	// 		get from kv if hash exists
	// 			if not o_create(hash)
	// 		okv_ref(hash)
	// 	o_write(chunk)
	// for each old_chunk:
	// 	okv_unref(hashes[old_chunk])

// 	// evtl ins item struct auslagern
// 
// 	EVP_MD_CTX_destroy(mdctx);
// 	printf("write: hash is: ");
// 	for(unsigned int i = 0; i < md_len; i++)
// 		printf("%02x", hash[i]);
// 	printf("\n");
// 
// 
// 	// FIXME see j_item_write_exec
// 	j_distributed_object_write(item->object, data, length, offset, bytes_written, batch);

	j_trace_leave(G_STRFUNC);
}

/**
 * Get the status of an item.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param item      An item.
 * \param batch     A batch.
 **/
void
j_item_get_status (JItem* item, JBatch* batch)
{
	g_return_if_fail(item != NULL);

	j_trace_enter(G_STRFUNC, NULL);

	// FIXME check j_item_get_status_exec
	j_distributed_object_status(item->object, &(item->status.modification_time), &(item->status.size), batch);

	j_trace_leave(G_STRFUNC);
}

/**
 * Returns an item's size.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param item An item.
 *
 * \return A size.
 **/
guint64
j_item_get_size (JItem* item)
{
	g_return_val_if_fail(item != NULL, 0);

	j_trace_enter(G_STRFUNC, NULL);
	j_trace_leave(G_STRFUNC);

	return item->status.size;
}

/**
 * Returns an item's modification time.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param item An item.
 *
 * \return A modification time.
 **/
gint64
j_item_get_modification_time (JItem* item)
{
	g_return_val_if_fail(item != NULL, 0);

	j_trace_enter(G_STRFUNC, NULL);
	j_trace_leave(G_STRFUNC);

	return item->status.modification_time;
}

/**
 * Returns the item's optimal access size.
 *
 * \author Michael Kuhn
 *
 * \code
 * JItem* item;
 * guint64 optimal_size;
 *
 * ...
 * optimal_size = j_item_get_optimal_access_size(item);
 * j_item_write(item, buffer, optimal_size, 0, &dummy, batch);
 * ...
 * \endcode
 *
 * \param item An item.
 *
 * \return An access size.
 */
guint64
j_item_get_optimal_access_size (JItem* item)
{
	g_return_val_if_fail(item != NULL, 0);

	j_trace_enter(G_STRFUNC, NULL);
	j_trace_leave(G_STRFUNC);

	return 512 * 1024;
}

/* Internal */

/**
 * Creates a new item.
 *
 * \author Michael Kuhn
 *
 * \code
 * JItem* i;
 *
 * i = j_item_new("JULEA");
 * \endcode
 *
 * \param collection   A collection.
 * \param name         An item name.
 * \param distribution A distribution.
 *
 * \return A new item. Should be freed with j_item_unref().
 **/
JItem*
j_item_new (JCollection* collection, gchar const* name, JDistribution* distribution)
{
	JItem* item = NULL;
	g_autofree gchar* path = NULL;

	g_return_val_if_fail(collection != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	j_trace_enter(G_STRFUNC, NULL);

	if (strpbrk(name, "/") != NULL)
	{
		goto end;
	}

	if (distribution == NULL)
	{
		distribution = j_distribution_new(J_DISTRIBUTION_ROUND_ROBIN);
	}

	item = g_slice_new(JItem);
	bson_oid_init(&(item->id), bson_context_get_default());
	item->name = g_strdup(name);
	item->credentials = j_credentials_new();
	item->distribution = distribution;
	item->status.age = g_get_real_time();
	item->status.size = 0;
	item->status.modification_time = g_get_real_time();
	item->collection = j_collection_ref(collection);
	item->ref_count = 1;

	item->hashes = g_array_new(FALSE, FALSE, sizeof(guchar*));
	item->chunk_size = 8; // small size for testing only

	path = g_build_path("/", j_collection_get_name(item->collection), item->name, NULL);
	item->kv = j_kv_new("items", path);
	item->kv_h = j_kv_new("item_hashes", path);
	
	item->object = j_distributed_object_new("item", path, item->distribution);

end:
	j_trace_leave(G_STRFUNC);

	return item;
}

/**
 * Creates a new item from a BSON object.
 *
 * \private
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param collection A collection.
 * \param b          A BSON object.
 *
 * \return A new item. Should be freed with j_item_unref().
 **/
JItem*
j_item_new_from_bson (JCollection* collection, bson_t const* b)
{
	JItem* item;
	g_autofree gchar* path = NULL;

	g_return_val_if_fail(collection != NULL, NULL);
	g_return_val_if_fail(b != NULL, NULL);

	j_trace_enter(G_STRFUNC, NULL);

	item = g_slice_new(JItem);
	item->name = NULL;
	item->credentials = j_credentials_new();
	item->distribution = NULL;
	item->status.age = 0;
	item->status.size = 0;
	item->status.modification_time = 0;
	item->collection = j_collection_ref(collection);
	item->ref_count = 1;

	j_item_deserialize(item, b);

	path = g_build_path("/", j_collection_get_name(item->collection), item->name, NULL);
	item->kv = j_kv_new("items", path);
	item->object = j_distributed_object_new("item", path, item->distribution);

	j_trace_leave(G_STRFUNC);

	return item;
}

/**
 * Returns an item's collection.
 *
 * \private
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param item An item.
 *
 * \return A collection.
 **/
JCollection*
j_item_get_collection (JItem* item)
{
	g_return_val_if_fail(item != NULL, NULL);

	j_trace_enter(G_STRFUNC, NULL);
	j_trace_leave(G_STRFUNC);

	return item->collection;
}

/**
 * Returns an item's credentials.
 *
 * \private
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param item An item.
 *
 * \return A collection.
 **/
JCredentials*
j_item_get_credentials (JItem* item)
{
	g_return_val_if_fail(item != NULL, NULL);

	j_trace_enter(G_STRFUNC, NULL);
	j_trace_leave(G_STRFUNC);

	return item->credentials;
}

/**
 * Serializes an item.
 *
 * \private
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param item      An item.
 * \param semantics A semantics object.
 *
 * \return A new BSON object. Should be freed with g_slice_free().
 **/
bson_t*
j_item_serialize (JItem* item, JSemantics* semantics)
{
	bson_t* b;
	bson_t* b_cred;
	bson_t* b_distribution;

	g_return_val_if_fail(item != NULL, NULL);

	j_trace_enter(G_STRFUNC, NULL);

	b = bson_new();
	b_cred = j_credentials_serialize(item->credentials);
	b_distribution = j_distribution_serialize(item->distribution);

	bson_append_oid(b, "_id", -1, &(item->id));
	bson_append_oid(b, "collection", -1, j_collection_get_id(item->collection));
	bson_append_utf8(b, "name", -1, item->name, -1);

	if (j_semantics_get(semantics, J_SEMANTICS_CONCURRENCY) == J_SEMANTICS_CONCURRENCY_NONE)
	{
		bson_t b_document[1];

		bson_append_document_begin(b, "status", -1, b_document);

		bson_append_int64(b_document, "size", -1, item->status.size);
		bson_append_int64(b_document, "modification_time", -1, item->status.modification_time);

		bson_append_document_end(b, b_document);

		bson_destroy(b_document);
	}

	bson_append_document(b, "credentials", -1, b_cred);
	bson_append_document(b, "distribution", -1, b_distribution);

	//bson_finish(b);

	bson_destroy(b_cred);
	bson_destroy(b_distribution);

	j_trace_leave(G_STRFUNC);

	return b;
}

static
void
j_item_deserialize_status (JItem* item, bson_t const* b)
{
	bson_iter_t iterator;

	g_return_if_fail(item != NULL);
	g_return_if_fail(b != NULL);

	j_trace_enter(G_STRFUNC, NULL);

	bson_iter_init(&iterator, b);

	while (bson_iter_next(&iterator))
	{
		gchar const* key;

		key = bson_iter_key(&iterator);

		if (g_strcmp0(key, "size") == 0)
		{
			item->status.size = bson_iter_int64(&iterator);
			item->status.age = g_get_real_time();
		}
		else if (g_strcmp0(key, "modification_time") == 0)
		{
			item->status.modification_time = bson_iter_int64(&iterator);
			item->status.age = g_get_real_time();
		}
	}

	j_trace_leave(G_STRFUNC);
}

/**
 * Deserializes an item.
 *
 * \private
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param item An item.
 * \param b    A BSON object.
 **/
void
j_item_deserialize (JItem* item, bson_t const* b)
{
	bson_iter_t iterator;

	g_return_if_fail(item != NULL);
	g_return_if_fail(b != NULL);

	j_trace_enter(G_STRFUNC, NULL);

	bson_iter_init(&iterator, b);

	while (bson_iter_next(&iterator))
	{
		gchar const* key;

		key = bson_iter_key(&iterator);

		if (g_strcmp0(key, "_id") == 0)
		{
			item->id = *bson_iter_oid(&iterator);
		}
		else if (g_strcmp0(key, "name") == 0)
		{
			g_free(item->name);
			item->name = g_strdup(bson_iter_utf8(&iterator, NULL /*FIXME*/));
		}
		else if (g_strcmp0(key, "status") == 0)
		{
			guint8 const* data;
			guint32 len;
			bson_t b_status[1];

			bson_iter_document(&iterator, &len, &data);
			bson_init_static(b_status, data, len);
			j_item_deserialize_status(item, b_status);
			bson_destroy(b_status);
		}
		else if (g_strcmp0(key, "credentials") == 0)
		{
			guint8 const* data;
			guint32 len;
			bson_t b_cred[1];

			bson_iter_document(&iterator, &len, &data);
			bson_init_static(b_cred, data, len);
			j_credentials_deserialize(item->credentials, b_cred);
			bson_destroy(b_cred);
		}
		else if (g_strcmp0(key, "distribution") == 0)
		{
			guint8 const* data;
			guint32 len;
			bson_t b_distribution[1];

			if (item->distribution != NULL)
			{
				j_distribution_unref(item->distribution);
			}

			bson_iter_document(&iterator, &len, &data);
			bson_init_static(b_distribution, data, len);
			item->distribution = j_distribution_new_from_bson(b_distribution);
			bson_destroy(b_distribution);
		}
	}

	j_trace_leave(G_STRFUNC);
}

/**
 * Returns an item's ID.
 *
 * \private
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param item An item.
 *
 * \return An ID.
 **/
bson_oid_t const*
j_item_get_id (JItem* item)
{
	g_return_val_if_fail(item != NULL, NULL);

	j_trace_enter(G_STRFUNC, NULL);
	j_trace_leave(G_STRFUNC);

	return &(item->id);
}

/**
 * Sets an item's modification time.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param item              An item.
 * \param modification_time A modification time.
 **/
void
j_item_set_modification_time (JItem* item, gint64 modification_time)
{
	g_return_if_fail(item != NULL);

	j_trace_enter(G_STRFUNC, NULL);
	item->status.age = g_get_real_time();
	item->status.modification_time = MAX(item->status.modification_time, modification_time);
	j_trace_leave(G_STRFUNC);
}

/**
 * Sets an item's size.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param item An item.
 * \param size A size.
 **/
void
j_item_set_size (JItem* item, guint64 size)
{
	g_return_if_fail(item != NULL);

	j_trace_enter(G_STRFUNC, NULL);
	item->status.age = g_get_real_time();
	item->status.size = size;
	j_trace_leave(G_STRFUNC);
}

/*
gboolean
j_item_write_exec (JList* operations, JSemantics* semantics)
{
	if (j_semantics_get(semantics, J_SEMANTICS_CONCURRENCY) == J_SEMANTICS_CONCURRENCY_NONE && FALSE)
	{
		bson_t b_document[1];
		bson_t cond[1];
		bson_t op[1];
		mongoc_client_t* mongo_connection;
		mongoc_collection_t* mongo_collection;
		mongoc_write_concern_t* write_concern;
		gint ret;

		j_helper_set_write_concern(write_concern, semantics);

		bson_init(cond);
		bson_append_oid(cond, "_id", -1, &(item->id));
		bson_append_int32(cond, "Status.ModificationTime", -1, item->status.modification_time);
		//bson_finish(cond);

		j_item_set_modification_time(item, g_get_real_time());

		bson_init(op);

		bson_append_document_begin(op, "$set", -1, b_document);

		if (max_offset > item->status.size)
		{
			j_item_set_size(item, max_offset);
			bson_append_int64(b_document, "Status.Size", -1, item->status.size);
		}

		bson_append_int64(b_document, "Status.ModificationTime", -1, item->status.modification_time);
		bson_append_document_end(op, b_document);

		//bson_finish(op);

		mongo_connection = j_connection_pool_pop_kv(0);
		mongo_collection = mongoc_client_get_collection(mongo_connection, "JULEA", "Items");

		ret = mongoc_collection_update(mongo_collection, MONGOC_UPDATE_NONE, cond, op, write_concern, NULL);

		j_connection_pool_push_kv(0, mongo_connection);

		if (!ret)
		{

		}

		bson_destroy(cond);
		bson_destroy(op);

		mongoc_write_concern_destroy(write_concern);
	}
}
*/

/*
gboolean
j_item_get_status_exec (JList* operations, JSemantics* semantics)
{
	if (semantics_consistency != J_SEMANTICS_CONSISTENCY_IMMEDIATE)
	{
		if (item->status.age >= (guint64)g_get_real_time() - G_USEC_PER_SEC)
		{
			continue;
		}
	}

	if (semantics_concurrency == J_SEMANTICS_CONCURRENCY_NONE)
	{
		bson_t result[1];
		gchar* path;

		bson_init(&opts);
		bson_append_int32(&opts, "limit", -1, 1);
		bson_append_document_begin(&opts, "projection", -1, &projection);

		bson_append_bool(&projection, "Status.Size", -1, TRUE);
		bson_append_bool(&projection, "Status.ModificationTime", -1, TRUE);

		bson_append_document_end(&opts, &projection);

		if (kv_backend != NULL)
		{
			path = g_build_path("/", j_collection_get_name(item->collection), item->name, NULL);
			ret = j_backend_kv_get(kv_backend, "items", path, result) && ret;
			g_free(path);
		}

		bson_init(&b);
		bson_append_oid(&b, "_id", -1, &(item->id));

		if (ret)
		{
			j_item_deserialize(item, result);
			bson_destroy(result);
		}
	}
}
*/

/**
 * @}
 **/