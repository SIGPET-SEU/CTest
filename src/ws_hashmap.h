//
// Created by lxyu on 24-10-16.
//

#ifndef LIBGCRYPT_WS_HASHMAP_H
#define LIBGCRYPT_WS_HASHMAP_H

#endif //LIBGCRYPT_WS_HASHMAP_H

#include <glib-2.0/glib.h>

typedef struct {
    GHashTable* header_key;
    GHashTable* header_iv;
    GHashTable* data_key;
    GHashTable* data_iv;
    GHashTable* response_token;
} key_map_t;

typedef struct vmess_master_key_match_group {
    const char *re_group_name;
    GHashTable *key_ht;
} vmess_key_match_group_t;

void keymap_init(key_map_t* km);

void keymap_cleanup(key_map_t* km);
