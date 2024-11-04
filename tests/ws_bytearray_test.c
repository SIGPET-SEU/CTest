//
// Created by lxyu on 24-10-17.
//

#include <check.h>
#include <stdlib.h>
#include "ws_bytearray.h"

// This test covers empty hashmap comparison.
START_TEST(string_assign_byte_array) {
        GString *string = g_string_new("Alice");
        GByteArray *array = g_byte_array_new_take((gpointer)string->str, string->len);
        ck_assert_msg(memcmp(string->str, array->data, string->len) == 0, "Expect equality");
    }
END_TEST

/*
 * This test covers conversion from byte array to its nul terminated hex representation.
 */
START_TEST(test_to_hex) {
#define LEN 5
        guchar bytes[LEN] = {15, 11, 10, 255, 12};
        const char* expect = "0F0B0AFF0C";
        gchar* actual = malloc(2*LEN+1);
        to_hex(bytes, LEN, actual);
        ck_assert_msg(strcmp(expect, actual) == 0, "Expect: %s\n, but got %s", expect, actual);
    }
END_TEST

Suite *byte_array_suite(void) {
    Suite *s = suite_create("ByteArray Suite");

    // Add the setup and teardown functions to the test suite
    TCase *tc_core = tcase_create("Core");
    // Add test cases that will use the shared variable
    tcase_add_test(tc_core, string_assign_byte_array);
    tcase_add_test(tc_core, test_to_hex);

    suite_add_tcase(s, tc_core);
    return s;
}

int main(void){
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = byte_array_suite();
    sr = srunner_create(s);
    srunner_set_fork_status (sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}