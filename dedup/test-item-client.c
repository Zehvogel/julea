#include <julea-config.h>

#include <glib.h>

#include <julea.h>
#include <julea-item.h>

static
void
test_item (void)
{
	guint const n = 1;

	for (guint i = 0; i < n; i++)
	{
		g_autoptr(JBatch) batch = NULL;
		g_autoptr(JCollection) collection = NULL;
		g_autoptr(JItemDedup) item = NULL;
		const char data[] = "1234567887654321"; //test-data-12345
		printf("sizeof(data): %lu\n", sizeof(data));
		char data2[sizeof(data)];
		guint64 bytes_written = 0;
		guint64 bytes_read = 0;

		batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
		collection = j_collection_create("test-collection", batch);
		item = j_item_dedup_create(collection, "test-item", NULL, batch);
		j_batch_execute(batch);

		printf("before write: data: %s\n", data);

		// strings und ihr doofer \0 terminator >.<
		j_item_dedup_write(item, &data, sizeof(data)-1, 0, &bytes_written, batch);
		j_batch_execute(batch);
		printf("bytes_written: %lu\n", bytes_written);
		j_item_dedup_read(item, data2, 8, 2, &bytes_read, batch);
		j_batch_execute(batch);
		data2[sizeof(data)-1] = '\0';
		printf("bytes_read: %lu\n", bytes_read);
		printf("after read: data: %s\n", data2);

		j_item_dedup_read(item, data2, 16, 0, &bytes_read, batch);
		j_batch_execute(batch);
		data2[sizeof(data)-1] = '\0';
		printf("bytes_read: %lu\n", bytes_read);
		printf("after read: data: %s\n", data2);

		g_assert(item != NULL);
	}
}

int
main (int argc, char** argv)
{
	(void) argc;
	(void) argv;

	test_item();
	printf("teeeest\n");
}
