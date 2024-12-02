//
// Created by lxyu on 24-10-16.
//

#include "ws_hashmap.h"

/*
 * TL;DR
 * Use this routine for keymap ONLY in tests. Use wmem in Wireshark.
 *
 * NOTE: The following routine is a wrapper function for GString, which will clean up
 * the underlying allocated memory. It is equivalent to g_string_free with free_segment == TRUE.
 *
 * This routine is passed to g_hash_table_new_full. In Wireshark, you MUST NOT use this.
 * Instead, each entry for the keymap is allocated using wmem framework, which will be free-ed
 * when the file lifecycle ends.
 *
 * PS: Maybe lambda functions are better, but C does not strictly support it.
 */
gchar *g_string_true_free(GString* string){
    return g_string_free(string, TRUE);
}

void keymap_init(key_map_t *km) {
    km->data_iv = g_hash_table_new_full((GHashFunc) g_string_hash, (GEqualFunc) g_string_equal,
                                        (GDestroyNotify) g_string_true_free, (GDestroyNotify) g_string_true_free);
    km->data_key = g_hash_table_new_full((GHashFunc) g_string_hash, (GEqualFunc) g_string_equal,
                                    (GDestroyNotify) g_string_true_free, (GDestroyNotify) g_string_true_free);
    km->header_iv = g_hash_table_new_full((GHashFunc) g_string_hash, (GEqualFunc) g_string_equal,
                                          (GDestroyNotify) g_string_true_free, (GDestroyNotify) g_string_true_free);
    km->header_key = g_hash_table_new_full((GHashFunc) g_string_hash, (GEqualFunc) g_string_equal,
                                           (GDestroyNotify) g_string_true_free, (GDestroyNotify) g_string_true_free);
    km->response_token = g_hash_table_new_full((GHashFunc) g_string_hash, (GEqualFunc) g_string_equal,
                                               (GDestroyNotify) g_string_true_free, (GDestroyNotify) g_string_true_free);
}

void keymap_cleanup(key_map_t *km) {
    g_hash_table_destroy(km->data_iv);
    g_hash_table_destroy(km->data_key);
    g_hash_table_destroy(km->header_iv);
    g_hash_table_destroy(km->header_key);
    g_hash_table_destroy(km->response_token);
}
