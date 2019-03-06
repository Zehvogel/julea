#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <hdf5.h>
#include "julea-hdf5-filter.h"

#define PLUGIN_ERROR 0
#define PLUGIN_OK 1

#pragma GCC diagnostic ignored "-Wunused-parameter"

H5PL_type_t H5PLget_plugin_type(void) {
  return H5PL_TYPE_FILTER;
}

static htri_t compressorCanCompress(hid_t dcpl_id, hid_t type_id, hid_t space_id);
static herr_t compressorSetLocal(hid_t pList, hid_t type, hid_t space);
static size_t compressorFilter(unsigned int flags, size_t cd_nelmts, const unsigned int cd_values[], size_t nbytes, size_t *buf_size, void **buf);

static size_t identifier = 0;

const void *H5PLget_plugin_info(void) {
  static H5Z_class2_t filterClass = {
    .version = H5Z_CLASS_T_VERS,
    .id = H5Z_FILTER_JULEA,
    .encoder_present = 1,
    .decoder_present = 1,
    .name = "julea",
    .can_apply = & compressorCanCompress,
    .set_local = & compressorSetLocal,
    .filter = & compressorFilter
  };
  return &filterClass;
}


static htri_t compressorCanCompress(hid_t dcpl_id, hid_t type_id, hid_t space_id) {
  return PLUGIN_OK;
}

static herr_t compressorSetLocal(hid_t pList, hid_t type_id, hid_t space) {
  return PLUGIN_OK;
}

static size_t compressorFilter(unsigned int flags, size_t cd_nelmts,
                     const unsigned int cd_values[], size_t nbytes,
                     size_t *buf_size, void **buf)
{
  char *outbuf = NULL;
  size_t outbuflen, outdatalen;
  int ret;
  if (flags & H5Z_FLAG_REVERSE) {

    /** Decompress data.
     **
     ** 
     **/


  } else {

    /** Compress data.
     **
     ** 
     **/
    // TODO: Identifier?
    gchar *item_name = g_strdup_printf("Variable: %s:%ld", getenv("H5REPACK_VARIABLE"), identifier);
    ++identifier;
    printf("%s\n", item_name);

    g_autoptr(JBatch) batch = NULL;
    g_autoptr(JCollection) collection = NULL;
    g_autoptr(JItemDedup) item = NULL;
    guint64 bytes_written = 0;
    guint64 bytes_read = 0;

    batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
    collection = j_collection_create("test-collection", batch);
    item = j_item_dedup_create(collection, item_name, NULL, batch);
    j_item_set_chunk_size(item, 2048);
    j_batch_execute(batch);

    j_item_dedup_write(item, *buf, nbytes, 0, &bytes_written, batch);
    j_batch_execute(batch);
    printf("bytes_written: %lu\n", bytes_written);
    *buf = item_name;
    return strlen(item_name);
  }
    return PLUGIN_OK;
}
