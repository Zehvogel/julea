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
		g_autoptr(JItem) item = NULL;
		const char data[] = "test-data";
		guint64 bytes_written = 0;

		batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
		collection = j_collection_create("test-collection", batch);
		item = j_item_create(collection, "test-item", NULL, batch);

		j_item_write (item, data, sizeof(data), 0, &bytes_written, batch);

		g_assert(item != NULL);
	}
}

int
main (int argc, char** argv)
{
	(void) argc;
	(void) argv;

	test_item();
	printf("teeest\n");
}
