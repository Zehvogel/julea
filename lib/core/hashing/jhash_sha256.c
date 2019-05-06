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

#include <hashing/jhash_sha256.h>
#include <openssl/evp.h>

void* sha256_context(void){
	EVP_MD_CTX *mdctx;
	mdctx = EVP_MD_CTX_create();
	return mdctx;
}

int sha256_init(void *ctx){
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	return 0;
}

int sha256_update(void *ctx, const void *data, size_t length){
	EVP_DigestUpdate(ctx, data, length);
	return 0;
}

int sha256_finalize(void *ctx, gchar **hash){
	guint md_len;
	guchar hash_gen[EVP_MAX_MD_SIZE];
	GString *hash_string = g_string_new (NULL);

	EVP_DigestFinal_ex(ctx, hash_gen, &md_len);
	// Generate the usable hash
	for(unsigned int i = 0; i < md_len; i++){
		g_string_append_printf(hash_string, "%02x", hash_gen[i]);
	}
	*hash = hash_string->str;
	return md_len;
}

int sha256_destroy(void *ctx){
	EVP_MD_CTX_destroy(ctx);
	return 0;
}

jhash_algorithm hash_sha256 = {
    sha256_context,
    sha256_init,
    sha256_update,
    sha256_finalize,
	sha256_destroy,
    "SHA256",
    J_HASH_SHA256
};


/**
 * @}
 **/
