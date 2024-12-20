//
// Created by lxyu on 24-10-15.
//
#include <check.h>
#include <stdlib.h>
#include <unistd.h>
#include "ws_regex.h"

key_map_t map;

void setup(void){
    keymap_init(&map);
}

void teardown(void){
    keymap_cleanup(&map);
}

// This test covers a GRegex that matches one-line string.
START_TEST (test_regex_simple_match)
{
    /* unit test code */
    GRegex *regex = vmess_compile_keyfile_regex();
    const char* data = "HEADER_KEY 7fc943ae0a5b1384012daf29e64106cc 0d3d64282120f7808ee531d4feb22357";
    const char* target_auth = "7fc943ae0a5b1384012daf29e64106cc";
    const char* target_secret = "0d3d64282120f7808ee531d4feb22357";
    GMatchInfo *mi;
    ck_assert_msg(g_regex_match_full(regex, data, -1, 0, G_REGEX_MATCH_ANCHORED, &mi, NULL),
                  "Expect a full match.");
    /* We have not captured the label, fetching it in GMatchInfo should return NULL */
    ck_assert_msg(!g_match_info_fetch_named(mi, "label"),
                  "Expect NULL.");
    char* auth = g_match_info_fetch_named(mi, "header_key");
    char* secret = g_match_info_fetch_named(mi, "secret");

    ck_assert_msg(strcmp(auth, target_auth) == 0, "Expect AUTH equality.");
    ck_assert_msg(strcmp(secret, target_secret) == 0, "Expect SECRET equality.");

    g_match_info_free(mi);
    g_free(auth);
    g_free(secret);
}
END_TEST

START_TEST (test_from_hex)
    {
        /* unit test code */
        GString *arr = g_string_new(NULL);

        const char* data_1 = "0d3d64282120";
        char hex_data_1[] = "\x0d\x3d\x64\x28\x21\x20";
        ck_assert_msg(from_hex(data_1, arr, strlen(data_1)), "Expect a successful conversion.");
        ck_assert_msg(memcmp(hex_data_1, arr->str, arr->len) == 0, "Expect memory equality.");

        g_string_free(arr, TRUE);
        arr = g_string_new(NULL);

        const char* data_2 = "0d00ff00ff00";
        char hex_data_2[] = "\x0d\x00\xff\x00\xff\x00";
        ck_assert_msg(from_hex(data_2, arr, strlen(data_2)), "Expect a successful conversion.");
        ck_assert_msg(memcmp(hex_data_2, arr->str, arr->len) == 0, "Expect memory equality.");

        g_string_free(arr, TRUE);
        arr = g_string_new(NULL);

        const char* data_3 = "0zs0ff00ff00";
        ck_assert_msg(!from_hex(data_3, arr, strlen(data_3)), "Expect a failed conversion.");

        g_string_free(arr, TRUE);
    }
END_TEST

START_TEST (test_from_hex_raw)
    {
        /* unit test code */
        const char* data_1 = "0d3d64282120";
        gchar *arr = g_malloc(strlen(data_1)/2 + 1);
        char hex_data_1[] = "\x0d\x3d\x64\x28\x21\x20";
        ck_assert_msg(from_hex_raw(data_1, arr, strlen(data_1)), "Expect a successful conversion.");
        ck_assert_msg(strcmp(hex_data_1, arr) == 0, "Expect memory equality.");

        g_free(arr);

        const char* data_2 = "0d00ff00ff00";
        arr = g_malloc(strlen(data_2)/2 + 1);
        char hex_data_2[] = "\x0d\x00\xff\x00\xff\x00";
        ck_assert_msg(from_hex_raw(data_2, arr, strlen(data_2)), "Expect a successful conversion.");
        ck_assert_msg(memcmp(hex_data_2, arr, strlen(data_2)/2 + 1) == 0, "Expect memory equality.");

        g_free(arr);
    }
END_TEST

// This test tests vmess_process_line, which builds a GRegex for a single line,
// and insert it into a key map.
START_TEST (test_vmess_process_line_single_line)
    {
        /* unit test code */


        const char* data = "HEADER_KEY 7fc943ae0a5b1384012daf29e64106cc 0d3d64282120f7808ee531d4feb22357\r\n";
        keylog_process_line(data, strlen(data), &map);

        GString *target_arr = g_string_new(NULL);
        const char* secret = "0d3d64282120f7808ee531d4feb22357";
        from_hex(secret, target_arr, strlen(secret));

        GString *auth = g_string_new(NULL);
        from_hex("7fc943ae0a5b1384012daf29e64106cc", auth, strlen("7fc943ae0a5b1384012daf29e64106cc"));
        GString *arr = (GString*) g_hash_table_lookup(map.header_key, auth);
        ck_assert_msg(arr->len == 16, "The secret should have the length of 16.");
        ck_assert_msg(memcmp(arr->str, target_arr->str, arr->len) == 0, "Expect the same content.");

        g_string_free(target_arr, TRUE);
        g_string_free(auth, TRUE);
    }
END_TEST

// This test tests keylog_read, which builds a GRegex for a key log file,
// and insert it into a key map.
START_TEST (test_keylog_read)
    {
        /* unit test code */
        const char* file_path = "../../data/keylog.txt";
        keylog_read(file_path, &map);

        /* Lookup test 1 */
        GString *auth_1 = g_string_new(NULL);
        from_hex("7fc943ae0a5b1384012daf29e64106cc", auth_1, strlen("7fc943ae0a5b1384012daf29e64106cc"));
        GString *target_arr_1 = g_string_new(NULL);
        const char* secret_1 = "d60ef24ddf435e70809d45edf5932d84";
        from_hex(secret_1, target_arr_1, strlen(secret_1));
        GString *HEADER_IV = (GString *)g_hash_table_lookup(map.header_iv, auth_1);
        ck_assert_msg(memcmp(HEADER_IV->str, target_arr_1->str, target_arr_1->len) == 0,
                      "Test case 1: Expect the same content.");

        /* Lookup test 2 */
        GString *auth_2 = g_string_new(NULL);
        from_hex("000943ae0a5b1384012daf29e64106cc", auth_2, strlen("000943ae0a5b1384012daf29e64106cc"));
        GString *target_arr_2 = g_string_new(NULL);
        const char* secret_2 = "222102ae535a83ba1580a39321373bc0";
        from_hex(secret_2, target_arr_2, strlen(secret_2));
        GString *DATA_KEY = (GString *)g_hash_table_lookup(map.data_key, auth_2);
        ck_assert_msg(memcmp(DATA_KEY->str, target_arr_2->str, target_arr_2->len) == 0,
                      "Test case 2: Expect the same content.");

        /* Lookup test 3 */
        GString *auth_3 = g_string_new(NULL);
        from_hex("111943ae0a5b1384012daf29e64106cc", auth_3, strlen("111943ae0a5b1384012daf29e64106cc"));
        GString *target_arr_3 = g_string_new(NULL);
        const char* secret_3 = "100d64282120f7808ee531d4feb22357";
        from_hex(secret_3, target_arr_3, strlen(secret_3));
        GString *HEADER_KEY = (GString *)g_hash_table_lookup(map.header_key, auth_3);
        ck_assert_msg(memcmp(HEADER_KEY->str, target_arr_3->str, target_arr_3->len) == 0,
                      "Test case 3: Expect the same content.");

        /* Lookup test 4 */
        GString *auth_4 = g_string_new(NULL);
        from_hex("111943ae0a5b1384012daf29e64106cc", auth_4, strlen("111943ae0a5b1384012daf29e64106cc"));
        GString *target_arr_4 = g_string_new(NULL);
        const char* secret_4 = "54";
        from_hex(secret_4, target_arr_4, strlen(secret_4));
        GString *RESPONSE_TOKEN = (GString *)g_hash_table_lookup(map.response_token, auth_4);
        ck_assert_msg(memcmp(RESPONSE_TOKEN->str, target_arr_4->str, target_arr_4->len) == 0,
                      "Test case 4: Expect the same content.");

        /* Lookup test 5 */
        GString *auth_5 = g_string_new(NULL);
        from_hex("7fc943ae0a5b1384012daf29e64106cc", auth_5, strlen("7fc943ae0a5b1384012daf29e64106cc"));
        GString *target_arr_5 = g_string_new(NULL);
        const char* secret_5 = "d702488b088ec8fc24eb0e3cc8e1544d";
        from_hex(secret_5, target_arr_5, strlen(secret_5));
        GString *DATA_IV = (GString *)g_hash_table_lookup(map.data_iv, auth_5);
        ck_assert_msg(memcmp(DATA_IV->str, target_arr_5->str, target_arr_5->len) == 0,
                      "Test case 5: Expect the same content.");

        /* Lookup test 6*/
        GString *auth_6 = g_string_new(NULL);
        from_hex("111143ae0a5b1384012daf29e64106cc", auth_6, strlen("111143ae0a5b1384012daf29e64106cc"));
        DATA_IV = (GString *)g_hash_table_lookup(map.data_iv, auth_6);
        ck_assert_msg(DATA_IV == NULL,
                      "Test case 6: Expect value not found.");


        /* Garbage collection code here */
        g_string_free(target_arr_1, TRUE);
        g_string_free(target_arr_2, TRUE);
        g_string_free(target_arr_3, TRUE);
        g_string_free(target_arr_4, TRUE);
        g_string_free(target_arr_5, TRUE);
        g_string_free(auth_1, TRUE);
        g_string_free(auth_2, TRUE);
        g_string_free(auth_3, TRUE);
        g_string_free(auth_4, TRUE);
        g_string_free(auth_5, TRUE);
        g_string_free(auth_6, TRUE);
    }
END_TEST

Suite * regex_suite(void){
    Suite *s;
    TCase *tc_core;

    s = suite_create("Regex");

    /* Core test case */
    tc_core = tcase_create("Core");
    tcase_add_checked_fixture(tc_core, setup, teardown);

    tcase_add_test(tc_core, test_regex_simple_match);
    tcase_add_test(tc_core, test_from_hex);
    tcase_add_test(tc_core, test_from_hex_raw);
    tcase_add_test(tc_core, test_vmess_process_line_single_line);
    tcase_add_test(tc_core, test_keylog_read);

    suite_add_tcase(s, tc_core);
    return s;
}

int main(void){
    /* Use this code piece to print WORKDIR */
//    char cwd[1024];
//    if (getcwd(cwd, sizeof(cwd)) != NULL) {
//        printf("Current working dir: %s\n", cwd);
//    }

    int number_failed;
    Suite *s;
    SRunner *sr;

    s = regex_suite();
    sr = srunner_create(s);
    srunner_set_fork_status (sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}