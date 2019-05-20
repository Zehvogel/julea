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

#include <hashing/jhash_xxhash.h>

#ifdef HAVE_XXHASH
#include "xxhash.h"

void* xxhash_context(void){
	XXH64_state_t* state;
	state = XXH64_createState();
	return state;
}

int xxhash_init(void *ctx){
	unsigned long long const seed = 0;   /* or any other value */
    return XXH64_reset(ctx, seed);
}

int xxhash_update(void *ctx, const void *data, size_t length){
	return XXH64_update(ctx, data, length);
}

int xxhash_finalize(void *ctx, gchar **hash){
	GString *hash_string = g_string_new (NULL);
	XXH64_hash_t xx_hash = XXH64_digest(ctx);
	// Generate the usable hash
	g_string_append_printf(hash_string, "%lli", xx_hash);
	
	*hash = hash_string->str;
	return hash_string->len;
}

int xxhash_destroy(void *ctx){
	return XXH64_freeState(ctx);
}

jhash_algorithm hash_xxhash = {
    xxhash_context,
    xxhash_init,
    xxhash_update,
    xxhash_finalize,
	xxhash_destroy,
    "XXHASH",
    J_HASH_XXHASH
};
#else
void* xxhash_context(void){
	g_error("XXHash is not available\n");
}

jhash_algorithm hash_xxhash = {
    xxhash_context,
    NULL,
    NULL,
    NULL,
	NULL,
    "XXHASH",
    J_HASH_XXHASH
};
#endif

/**
 * @}
 **/
