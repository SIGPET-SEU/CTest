//
// Created by lxyu on 24-10-16.
//


#include <check.h>
#include <stdlib.h>
#include "ws_hashmap.h"

GHashTable *map;

void setup(void){
    map = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
}

void teardown(void){
    g_hash_table_destroy(map);
}

// This test covers empty hashmap size.
START_TEST(empty_hashmap) {
        ck_assert_msg(g_hash_table_size(map) == 0, "Expect an empty map.\n");
    }
END_TEST

// This test covers hashmaps with 1 entry lookup.
START_TEST(singleton_hashmap) {
        char* key = g_strdup("Alice");
        GByteArray *value = g_byte_array_new_take((guint8 *)key, strlen(key));
        g_hash_table_insert(map, key, value);
        GByteArray *lookup_value = g_hash_table_lookup(map, "Alice");
        /* They should point to the same address */
        ck_assert_msg((gpointer)value == (gpointer)lookup_value, "Expect equal memory address.\n");
        ck_assert_msg(memcmp(lookup_value->data, value->data, strlen(key)) == 0, "Expect equal content.\n");
    }
END_TEST

// This test covers hashmaps with multiple entries comparison,
// while the entry order should not matter.
START_TEST(multi_entry_hashmap) {
    }
END_TEST

Suite *hashmap_suite(void) {
    Suite *s = suite_create("Hashmap Suite");

    // Add the setup and teardown functions to the test suite
    TCase *tc_core = tcase_create("Core");
    tcase_add_checked_fixture(tc_core, setup, teardown);

    // Add test cases that will use the shared variable
    tcase_add_test(tc_core, empty_hashmap);
    tcase_add_test(tc_core, singleton_hashmap);

    suite_add_tcase(s, tc_core);
    return s;
}

int main(void){
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = hashmap_suite();
    sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}