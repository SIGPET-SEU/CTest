//
// Created by lxyu on 24-10-20.
//
#include "ws_encrypt_vmess.h"
#include <check.h>
#include <stdlib.h>
#include <unistd.h>

gcry_cipher_hd_t handle;

void setup(){

}

void teardown(){
    gcry_cipher_close(handle);
}

/*
 * This test covers encryption and decryption on text.txt using AES-128-GCM algorithm.
 * The key and IV are created manually.
 */
START_TEST(text_encrypt_aes_128_gcm) {
//        /* Open the text file we want to encrypt, open it as byte stream file. */
//        FILE *in, *out;
//        const char *in_file_path = "../../data/text.txt";
//        const char *out_file_path = "../../data/encrypted_text.txt";
//        in = fopen(in_file_path, "rb");
//        if(!in) fprintf(stderr, "Error occurs when open input file.\n");
//        out = fopen(out_file_path, "wb");
//        if(!out) fprintf(stderr, "Error occurs when open output file.\n");
//
//        /* Open a cipher, then setup cipher key and iv. Optionally, one could attach some AD to the encryption. */
//        unsigned char key[AES_KEY_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//                                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
//
//        unsigned char iv[GCM_IV_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//                                            0x08, 0x09, 0x0A, 0x0B};
//        const char *associated_data = "authentication";
//
//        /* Close the file */
//        if(out != NULL) fclose(out);
//        if(in != NULL) fclose(in);
    }
END_TEST

Suite *encrypt_suite(void) {
    Suite *s = suite_create("Encrypt Suite");

    // Add the setup and teardown functions to the test suite
    TCase *tc_core = tcase_create("Core");
    tcase_add_checked_fixture(tc_core, setup, teardown);

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