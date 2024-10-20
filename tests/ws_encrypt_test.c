//
// Created by lxyu on 24-10-20.
//
#include <glib.h>
#include <check.h>
#include <stdlib.h>
#include <unistd.h>



Suite *encrypt_suite(void) {
    Suite *s = suite_create("Encrypt Suite");

    // Add the setup and teardown functions to the test suite
    TCase *tc_core = tcase_create("Core");

    // Add test cases that will use the shared variable

    suite_add_tcase(s, tc_core);
    return s;
}

int main(void){
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = encrypt_suite();
    sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}