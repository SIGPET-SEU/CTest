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

Suite *byte_array_suite(void) {
    Suite *s = suite_create("ByteArray Suite");

    // Add the setup and teardown functions to the test suite
    TCase *tc_core = tcase_create("Core");
    // Add test cases that will use the shared variable
    tcase_add_test(tc_core, string_assign_byte_array);

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