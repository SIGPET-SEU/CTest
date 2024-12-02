//
// Created by lxyu on 24-10-16.
//

#include "ws_hashmap.h"

void keymap_init(key_map_t *km) {
    km->data_iv = g_hash_table_new((GHashFunc) g_string_hash, (GEqualFunc) g_string_equal);
    km->data_key = g_hash_table_new((GHashFunc) g_string_hash, (GEqualFunc) g_string_equal);
    km->header_iv = g_hash_table_new((GHashFunc) g_string_hash, (GEqualFunc) g_string_equal);
    km->header_key = g_hash_table_new((GHashFunc) g_string_hash, (GEqualFunc) g_string_equal);
    km->response_token = g_hash_table_new((GHashFunc) g_string_hash, (GEqualFunc) g_string_equal);
}

void keymap_cleanup(key_map_t *km) {
    g_hash_table_destroy(km->data_iv);
    g_hash_table_destroy(km->data_key);
    g_hash_table_destroy(km->header_iv);
    g_hash_table_destroy(km->header_key);
    g_hash_table_destroy(km->response_token);
}
